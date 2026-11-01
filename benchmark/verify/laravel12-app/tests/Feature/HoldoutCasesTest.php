<?php

namespace Tests\Feature;

use App\Models\Article;
use App\Models\Import;
use App\Models\Listing;
use App\Models\Message;
use App\Models\Subscription;
use App\Models\User;
use Database\Factories\ArticleFactory;
use Database\Factories\ImportFactory;
use Database\Factories\ListingFactory;
use Database\Factories\MessageFactory;
use Database\Factories\SubscriptionFactory;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\Feature\Concerns\VerifiesBenchmark;
use Tests\Support\WakeupProbe;
use Tests\TestCase;

class HoldoutCasesTest extends TestCase
{
    use RefreshDatabase;
    use VerifiesBenchmark;

    protected function setUp(): void
    {
        parent::setUp();
        WakeupProbe::$woken = false;
    }

    /** @return array{0: Message, 1: Message} */
    private function twoInboxes(): array
    {
        return [
            MessageFactory::new()->for($this->owner())->create(),
            MessageFactory::new()->for($this->attacker())->create(),
        ];
    }

    /** @return array{0: Subscription, 1: Subscription} */
    private function twoSubscriptions(): array
    {
        return [
            SubscriptionFactory::new()->for($this->owner())->create(),
            SubscriptionFactory::new()->for($this->attacker())->create(),
        ];
    }

    private function checkpoint(mixed $state): string
    {
        return base64_encode(serialize($state));
    }

    public function testIdorBulkIdsUnscopedVulnerable(): void
    {
        [$ownerMessage, $attackerMessage] = $this->twoInboxes();

        $r = $this->actingAs($this->attacker())->patchJson('/vuln/messages/archive', ['ids' => [$ownerMessage->id, $attackerMessage->id]]);

        $this->assertExploited($r);
        $this->assertSame(2, $r->json('archived'));
        $this->assertNotNull(Message::find($ownerMessage->id)->archived_at);
    }

    public function testIdorBulkIdsUnscopedSafe(): void
    {
        [$ownerMessage, $attackerMessage] = $this->twoInboxes();

        $r = $this->actingAs($this->attacker())->patchJson('/safe/messages/archive', ['ids' => [$ownerMessage->id, $attackerMessage->id]]);
        $this->assertSame(200, $r->getStatusCode());
        $this->assertSame(1, $r->json('archived'));
        $this->assertNull(Message::find($ownerMessage->id)->archived_at);
        $this->assertNotNull(Message::find($attackerMessage->id)->archived_at);

        $r = $this->actingAs($this->owner())->patchJson('/safe/messages/archive', ['ids' => [$ownerMessage->id]]);
        $this->assertOwnerWorks($r);
        $this->assertNotNull(Message::find($ownerMessage->id)->archived_at);
    }

    public function testMissingAuthzAdminSuspendVulnerable(): void
    {
        $victim = $this->owner();

        $r = $this->actingAs($this->attacker())->postJson("/vuln/users/{$victim->id}/suspend");

        $this->assertExploited($r);
        $this->assertNotNull(User::find($victim->id)->suspended_at);
    }

    public function testMissingAuthzAdminSuspendSafe(): void
    {
        $victim = User::factory()->create();

        $this->assertBlocked($this->actingAs($this->attacker())->postJson("/safe/users/{$victim->id}/suspend"), 403);
        $this->assertNull(User::find($victim->id)->suspended_at);

        $admin = $this->owner();
        $admin->forceFill(['role' => 'admin'])->save();
        $this->assertOwnerWorks($this->actingAs($admin)->postJson("/safe/users/{$victim->id}/suspend"));
        $this->assertNotNull(User::find($victim->id)->suspended_at);
    }

    public function testIdorGateClosureIgnoresModelVulnerable(): void
    {
        [$ownerSubscription] = $this->twoSubscriptions();

        $r = $this->actingAs($this->attacker())->postJson("/vuln/subscriptions/{$ownerSubscription->id}/pause", ['weeks' => 8]);

        $this->assertExploited($r);
        $this->assertSame('paused', Subscription::find($ownerSubscription->id)->status);
        $this->assertSame($this->owner()->id, Subscription::find($ownerSubscription->id)->user_id);
    }

    public function testIdorGateClosureIgnoresModelSafe(): void
    {
        [$ownerSubscription] = $this->twoSubscriptions();

        $this->assertBlocked($this->actingAs($this->attacker())->postJson("/safe/subscriptions/{$ownerSubscription->id}/pause", ['weeks' => 8]), 403);
        $this->assertSame('active', Subscription::find($ownerSubscription->id)->status);

        $this->assertOwnerWorks($this->actingAs($this->owner())->postJson("/safe/subscriptions/{$ownerSubscription->id}/pause", ['weeks' => 2]));
        $this->assertSame('paused', Subscription::find($ownerSubscription->id)->status);
    }

    public function testMassAssignValidatedSensitiveRuleVulnerable(): void
    {
        $listing = ListingFactory::new()->for($this->attacker())->create();

        $r = $this->actingAs($this->attacker())->patchJson("/vuln/listings/{$listing->id}", ['title' => 'Vintage lamp', 'commission_rate' => 0]);

        $this->assertExploited($r);
        $this->assertSame('Vintage lamp', Listing::find($listing->id)->title);
        $this->assertEquals(0, Listing::find($listing->id)->commission_rate);

        $other = ListingFactory::new()->for($this->owner())->create();
        $this->assertBlocked($this->actingAs($this->attacker())->patchJson("/vuln/listings/{$other->id}", ['title' => 'Mine now']), 403);
    }

    public function testMassAssignValidatedSensitiveRuleSafe(): void
    {
        $listing = ListingFactory::new()->for($this->attacker())->create();

        $r = $this->actingAs($this->attacker())->patchJson("/safe/listings/{$listing->id}", ['title' => 'Vintage lamp', 'commission_rate' => 0]);
        $this->assertOwnerWorks($r);
        $this->assertSame('Vintage lamp', Listing::find($listing->id)->title);
        $this->assertEquals(12, Listing::find($listing->id)->commission_rate);

        $other = ListingFactory::new()->for($this->owner())->create();
        $this->assertBlocked($this->actingAs($this->attacker())->patchJson("/safe/listings/{$other->id}", ['title' => 'Mine now']), 403);
        $this->assertNotSame('Mine now', Listing::find($other->id)->title);
    }

    public function testWorkflowPublishSkipsApprovalVulnerable(): void
    {
        $draft = ArticleFactory::new()->for($this->owner())->create();

        $r = $this->actingAs($this->owner())->postJson("/vuln/articles/{$draft->id}/publish");

        $this->assertExploited($r);
        $this->assertSame('published', Article::find($draft->id)->status);
        $this->assertNull(Article::find($draft->id)->approved_by);

        $other = ArticleFactory::new()->for($this->owner())->create();
        $this->assertBlocked($this->actingAs($this->attacker())->postJson("/vuln/articles/{$other->id}/publish"), 403);
        $this->assertSame('draft', Article::find($other->id)->status);
    }

    public function testWorkflowPublishSkipsApprovalSafe(): void
    {
        $draft = ArticleFactory::new()->for($this->owner())->create();

        $this->assertBlocked($this->actingAs($this->owner())->postJson("/safe/articles/{$draft->id}/publish"), 403);
        $this->assertSame('draft', Article::find($draft->id)->status);
        $this->assertNull(Article::find($draft->id)->published_at);

        $approved = ArticleFactory::new()->for($this->owner())->create([
            'status' => 'approved', 'approved_by' => $this->attacker()->id, 'approved_at' => now(),
        ]);
        $this->assertOwnerWorks($this->actingAs($this->owner())->postJson("/safe/articles/{$approved->id}/publish"));
        $this->assertSame('published', Article::find($approved->id)->status);

        $this->assertBlocked($this->actingAs($this->attacker())->postJson("/safe/articles/{$approved->id}/publish"), 403);
    }

    public function testInsecureDeserializationRequestCheckpointVulnerable(): void
    {
        $r = $this->actingAs($this->attacker())->postJson('/vuln/imports/resume', ['checkpoint' => $this->checkpoint(new WakeupProbe())]);

        $this->assertTrue(WakeupProbe::$woken, 'unserialize() should have run __wakeup(); got '.$r->getStatusCode().': '.substr((string) $r->getContent(), 0, 200));
    }

    public function testInsecureDeserializationRequestCheckpointSafe(): void
    {
        $this->assertBlocked($this->actingAs($this->attacker())->postJson('/safe/imports/resume', ['checkpoint' => $this->checkpoint(new WakeupProbe())]), 422);
        $this->assertFalse(WakeupProbe::$woken);

        $import = ImportFactory::new()->for($this->owner())->create();
        $r = $this->actingAs($this->owner())->postJson('/safe/imports/resume', ['checkpoint' => $this->checkpoint(['import_id' => $import->id, 'offset' => 250])]);
        $this->assertOwnerWorks($r);
        $this->assertSame(250, Import::find($import->id)->processed_rows);

        $other = ImportFactory::new()->for($this->owner())->create();
        $this->assertBlocked($this->actingAs($this->attacker())->postJson('/safe/imports/resume', ['checkpoint' => $this->checkpoint(['import_id' => $other->id, 'offset' => 9])]), 404);
        $this->assertSame(0, Import::find($other->id)->processed_rows);
    }
}
