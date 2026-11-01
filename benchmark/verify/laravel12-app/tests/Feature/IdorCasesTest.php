<?php

namespace Tests\Feature;

use App\Models\Address;
use App\Models\Contact;
use App\Models\Product;
use App\Models\Review;
use App\Models\Store;
use App\Models\Team;
use App\Models\Transfer;
use App\Models\User;
use App\Models\Withdrawal;
use Database\Factories\AddressFactory;
use Database\Factories\ContactFactory;
use Database\Factories\OrganizationFactory;
use Database\Factories\PayoutFactory;
use Database\Factories\ProductFactory;
use Database\Factories\ProjectFactory;
use Database\Factories\ReviewFactory;
use Database\Factories\StatementFactory;
use Database\Factories\StoreFactory;
use Database\Factories\TeamFactory;
use Database\Factories\TicketFactory;
use Database\Factories\TransferFactory;
use Database\Factories\WithdrawalFactory;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\Feature\Concerns\VerifiesBenchmark;
use Tests\TestCase;

class IdorCasesTest extends TestCase
{
    use RefreshDatabase;
    use VerifiesBenchmark;

    private function merchant(User $user): User
    {
        $user->forceFill(['role' => 'merchant'])->save();

        return $user;
    }

    private function ownersStore(): Store
    {
        $store = StoreFactory::new()->for($this->merchant($this->owner()))->create();
        PayoutFactory::new()->for($store)->create(['iban' => 'GB00OWNERIBAN0001']);

        return $store;
    }

    /** @return array{0: Team, 1: Team, 2: int} */
    private function twoTeams(): array
    {
        $attackerTeam = TeamFactory::new()->create();
        $attackerTeam->members()->attach($this->attacker());
        $ownerTeam = TeamFactory::new()->create();
        $ownerTeam->members()->attach($this->owner());
        $project = ProjectFactory::new()->for($ownerTeam)->create(['name' => 'Owner Secret Project']);

        return [$attackerTeam, $ownerTeam, $project->id];
    }

    private function twoOrganizations(): void
    {
        $attackerOrg = OrganizationFactory::new()->create();
        $ownerOrg = OrganizationFactory::new()->create();
        $this->attacker()->forceFill(['organization_id' => $attackerOrg->id])->save();
        $this->owner()->forceFill(['organization_id' => $ownerOrg->id])->save();
        TicketFactory::new()->for($ownerOrg)->create(['subject' => 'Owner org outage']);
        TicketFactory::new()->for($attackerOrg)->create(['subject' => 'Attacker org question']);
    }

    private function deletedOwnerContact(): Contact
    {
        $contact = ContactFactory::new()->for($this->owner())->create(['email' => 'owner-contact@example.test']);
        $contact->delete();

        return $contact;
    }

    private function reviewOnAttackersProduct(): Review
    {
        $product = ProductFactory::new()->for($this->attacker())->create();

        return ReviewFactory::new()->for($this->owner())->for($product, 'reviewable')->create(['rating' => 1, 'body' => 'Broke in a week']);
    }

    private function ownersAddress(): Address
    {
        return AddressFactory::new()->for($this->owner())->create(['line1' => '1 Owner Street', 'city' => 'Leeds', 'postcode' => 'LS1 1AA']);
    }

    private function seedStatements(): void
    {
        StatementFactory::new()->for($this->owner())->create(['period' => '2026-09', 'closing_balance' => 98765.43]);
        StatementFactory::new()->for($this->attacker())->create(['period' => '2026-10', 'closing_balance' => 10]);
    }

    public function testIdorRoleOnlyMiddlewareVulnerable(): void
    {
        $store = $this->ownersStore();

        $r = $this->actingAs($this->merchant($this->attacker()))->getJson("/vuln/stores/{$store->id}/payouts");

        $this->assertExploited($r);
        $this->assertStringContainsString('GB00OWNERIBAN0001', $r->getContent());
    }

    public function testIdorRoleOnlyMiddlewareSafe(): void
    {
        $store = $this->ownersStore();

        $r = $this->actingAs($this->merchant($this->attacker()))->getJson("/safe/stores/{$store->id}/payouts");
        $this->assertBlocked($r, 403);
        $this->assertStringNotContainsString('GB00OWNERIBAN0001', $r->getContent());

        $r = $this->actingAs($this->owner())->getJson("/safe/stores/{$store->id}/payouts");
        $this->assertOwnerWorks($r);
        $this->assertStringContainsString('GB00OWNERIBAN0001', $r->getContent());
    }

    public function testIdorNestedUnscopedBindingVulnerable(): void
    {
        [$attackerTeam, , $projectId] = $this->twoTeams();

        $r = $this->actingAs($this->attacker())->getJson("/vuln/teams/{$attackerTeam->id}/projects/{$projectId}");

        $this->assertExploited($r);
        $this->assertStringContainsString('Owner Secret Project', $r->getContent());
    }

    public function testIdorNestedUnscopedBindingSafe(): void
    {
        [$attackerTeam, $ownerTeam, $projectId] = $this->twoTeams();

        $r = $this->actingAs($this->attacker())->getJson("/safe/teams/{$attackerTeam->id}/projects/{$projectId}");
        $this->assertBlocked($r, 404);
        $this->assertStringNotContainsString('Owner Secret Project', $r->getContent());

        $this->assertBlocked($this->actingAs($this->attacker())->getJson("/safe/teams/{$ownerTeam->id}/projects/{$projectId}"), 403);

        $r = $this->actingAs($this->owner())->getJson("/safe/teams/{$ownerTeam->id}/projects/{$projectId}");
        $this->assertOwnerWorks($r);
        $this->assertStringContainsString('Owner Secret Project', $r->getContent());
    }

    public function testIdorTenantListUnscopedVulnerable(): void
    {
        $this->twoOrganizations();

        $r = $this->actingAs($this->attacker())->getJson('/vuln/tickets');

        $this->assertExploited($r);
        $this->assertStringContainsString('Owner org outage', $r->getContent());
    }

    public function testIdorTenantListUnscopedSafe(): void
    {
        $this->twoOrganizations();

        $r = $this->actingAs($this->attacker())->getJson('/safe/tickets?status=open');
        $this->assertSame(200, $r->getStatusCode());
        $this->assertStringNotContainsString('Owner org outage', $r->getContent());
        $this->assertStringContainsString('Attacker org question', $r->getContent());

        $r = $this->actingAs($this->owner())->getJson('/safe/tickets');
        $this->assertOwnerWorks($r);
        $this->assertStringContainsString('Owner org outage', $r->getContent());
    }

    public function testIdorWithTrashedRestoreVulnerable(): void
    {
        $contact = $this->deletedOwnerContact();

        $r = $this->actingAs($this->attacker())->postJson("/vuln/contacts/{$contact->id}/restore");

        $this->assertExploited($r);
        $this->assertStringContainsString('owner-contact@example.test', $r->getContent());
        $this->assertNotNull(Contact::find($contact->id));
    }

    public function testIdorWithTrashedRestoreSafe(): void
    {
        $contact = $this->deletedOwnerContact();

        $r = $this->actingAs($this->attacker())->postJson("/safe/contacts/{$contact->id}/restore");
        $this->assertBlocked($r, 404);
        $this->assertStringNotContainsString('owner-contact@example.test', $r->getContent());
        $this->assertNull(Contact::find($contact->id));

        $r = $this->actingAs($this->owner())->postJson("/safe/contacts/{$contact->id}/restore");
        $this->assertOwnerWorks($r);
        $this->assertNotNull(Contact::find($contact->id));
    }

    public function testIdorPolymorphicParentCheckVulnerable(): void
    {
        $review = $this->reviewOnAttackersProduct();

        $r = $this->actingAs($this->attacker())->patchJson("/vuln/reviews/{$review->id}", ['rating' => 5, 'body' => 'Best purchase ever']);

        $this->assertExploited($r);
        $this->assertSame(5, (int) Review::find($review->id)->rating);
        $this->assertSame('Best purchase ever', Review::find($review->id)->body);
    }

    public function testIdorPolymorphicParentCheckSafe(): void
    {
        $review = $this->reviewOnAttackersProduct();

        $this->assertBlocked($this->actingAs($this->attacker())->patchJson("/safe/reviews/{$review->id}", ['rating' => 5, 'body' => 'Best purchase ever']), 403);
        $this->assertSame('Broke in a week', Review::find($review->id)->body);

        $this->assertOwnerWorks($this->actingAs($this->owner())->patchJson("/safe/reviews/{$review->id}", ['rating' => 2, 'body' => 'Replaced under warranty']));
        $this->assertSame('Replaced under warranty', Review::find($review->id)->body);
        $this->assertInstanceOf(Product::class, Review::find($review->id)->reviewable);
    }

    public function testIdorUpdateUnscopedRelationVulnerable(): void
    {
        $address = $this->ownersAddress();

        $r = $this->actingAs($this->attacker())->putJson("/vuln/addresses/{$address->id}", ['line1' => '9 Drop Lane', 'city' => 'Hull', 'postcode' => 'HU1 1AA']);

        $this->assertExploited($r);
        $this->assertSame('9 Drop Lane', Address::find($address->id)->line1);
        $this->assertSame($this->owner()->id, Address::find($address->id)->user_id);
    }

    public function testIdorUpdateUnscopedRelationSafe(): void
    {
        $address = $this->ownersAddress();

        $this->assertBlocked($this->actingAs($this->attacker())->putJson("/safe/addresses/{$address->id}", ['line1' => '9 Drop Lane', 'city' => 'Hull', 'postcode' => 'HU1 1AA']), 404);
        $this->assertSame('1 Owner Street', Address::find($address->id)->line1);

        $this->assertOwnerWorks($this->actingAs($this->owner())->putJson("/safe/addresses/{$address->id}", ['line1' => '2 New Road', 'city' => 'York', 'postcode' => 'YO1 1AA']));
        $this->assertSame('2 New Road', Address::find($address->id)->line1);
    }

    public function testIdorPolicyWrongAttributeVulnerable(): void
    {
        $transfer = TransferFactory::new()->for($this->owner())->create(['created_by' => $this->attacker()->id]);

        $r = $this->actingAs($this->attacker())->postJson("/vuln/transfers/{$transfer->id}/approve");

        $this->assertExploited($r);
        $this->assertSame('approved', Transfer::find($transfer->id)->status);
        $this->assertSame($this->owner()->id, Transfer::find($transfer->id)->user_id);
    }

    public function testIdorPolicyWrongAttributeSafe(): void
    {
        $withdrawal = WithdrawalFactory::new()->for($this->owner())->create(['created_by' => $this->attacker()->id]);

        $this->assertBlocked($this->actingAs($this->attacker())->postJson("/safe/withdrawals/{$withdrawal->id}/approve"), 403);
        $this->assertSame('pending', Withdrawal::find($withdrawal->id)->status);

        $this->assertOwnerWorks($this->actingAs($this->owner())->postJson("/safe/withdrawals/{$withdrawal->id}/approve"));
        $this->assertSame('approved', Withdrawal::find($withdrawal->id)->status);
    }

    public function testIdorQueryStringUserIdVulnerable(): void
    {
        $this->seedStatements();

        $r = $this->actingAs($this->attacker())->getJson('/vuln/statements?user_id='.$this->owner()->id);

        $this->assertExploited($r);
        $this->assertStringContainsString('98765.43', $r->getContent());
    }

    public function testIdorQueryStringUserIdSafe(): void
    {
        $this->seedStatements();

        $r = $this->actingAs($this->attacker())->getJson('/safe/statements?user_id='.$this->owner()->id);
        $this->assertSame(200, $r->getStatusCode());
        $this->assertStringNotContainsString('98765.43', $r->getContent());
        $this->assertStringContainsString('2026-10', $r->getContent());

        $r = $this->actingAs($this->owner())->getJson('/safe/statements');
        $this->assertOwnerWorks($r);
        $this->assertStringContainsString('98765.43', $r->getContent());
    }
}
