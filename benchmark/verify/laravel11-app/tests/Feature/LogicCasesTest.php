<?php

namespace Tests\Feature;

use App\Models\Account;
use App\Models\Member;
use App\Models\Order;
use App\Models\Team;
use App\Models\Workspace;
use Database\Factories\AccountFactory;
use Database\Factories\MemberFactory;
use Database\Factories\OrderFactory;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Sanctum\Sanctum;
use Tests\Feature\Concerns\VerifiesBenchmark;
use Tests\Support\WakeupProbe;
use Tests\TestCase;

class LogicCasesTest extends TestCase
{
    use RefreshDatabase;
    use VerifiesBenchmark;

    protected function setUp(): void
    {
        parent::setUp();
        WakeupProbe::$woken = false;
    }

    public function testMassAssignGuardedEmptyVulnerable(): void
    {
        $account = AccountFactory::new()->for($this->attacker())->create();

        $r = $this->actingAs($this->attacker())->putJson('/vuln/account', [
            'name' => 'Mallory', 'email' => 'mallory@example.test', 'is_admin' => 1, 'balance' => 999999, 'plan' => 'enterprise',
        ]);

        $this->assertExploited($r);
        $fresh = Account::find($account->id);
        $this->assertSame('Mallory', $fresh->name);
        $this->assertTrue($fresh->is_admin);
        $this->assertEquals(999999, $fresh->balance);
        $this->assertSame('enterprise', $fresh->plan);
    }

    public function testMassAssignGuardedEmptySafe(): void
    {
        $member = MemberFactory::new()->for($this->attacker())->create(['name' => 'Before', 'email' => 'before@example.test']);

        $r = $this->actingAs($this->attacker())->putJson('/safe/account', [
            'name' => 'Mallory', 'email' => 'mallory@example.test', 'is_admin' => 1, 'balance' => 999999, 'plan' => 'enterprise',
        ]);

        $this->assertOwnerWorks($r);
        $fresh = Member::find($member->id);
        $this->assertSame('Mallory', $fresh->name);
        $this->assertSame('mallory@example.test', $fresh->email);
        $this->assertArrayNotHasKey('is_admin', $fresh->getAttributes());
        $this->assertArrayNotHasKey('balance', $fresh->getAttributes());
        $this->assertArrayNotHasKey('plan', $fresh->getAttributes());
        $this->assertStringNotContainsString('999999', $r->getContent());
    }

    public function testMassAssignSensitiveFillableVulnerable(): void
    {
        $r = $this->actingAs($this->attacker())->postJson('/vuln/teams', ['name' => 'Planted', 'owner_id' => $this->owner()->id]);

        $this->assertExploited($r);
        $team = Team::where('name', 'Planted')->firstOrFail();
        $this->assertSame($this->owner()->id, $team->owner_id);
    }

    public function testMassAssignSensitiveFillableSafe(): void
    {
        $r = $this->actingAs($this->attacker())->postJson('/safe/workspaces', ['name' => 'Planted', 'owner_id' => $this->owner()->id]);

        $this->assertOwnerWorks($r);
        $workspace = Workspace::where('name', 'Planted')->firstOrFail();
        $this->assertSame($this->attacker()->id, $workspace->owner_id);
        $this->assertNotSame($this->owner()->id, $workspace->owner_id);
    }

    public function testInsecureDeserializationCookieVulnerable(): void
    {
        Sanctum::actingAs($this->attacker());

        $r = $this->withCredentials()->withUnencryptedCookie('cart', serialize(new WakeupProbe()))->putJson('/api/vuln/cart');

        $this->assertTrue(WakeupProbe::$woken, 'unserialize() should have run __wakeup(); got '.$r->getStatusCode().': '.substr((string) $r->getContent(), 0, 200));
    }

    public function testInsecureDeserializationCookieSafe(): void
    {
        Sanctum::actingAs($this->attacker());

        $this->withCredentials()->withUnencryptedCookie('cart', serialize(new WakeupProbe()))->putJson('/api/safe/cart');

        $this->assertFalse(WakeupProbe::$woken);
    }

    public function testWorkflowRefundAnyStatusVulnerable(): void
    {
        $order = OrderFactory::new()->for($this->owner())->create(['status' => 'pending']);

        $r = $this->actingAs($this->owner())->postJson("/vuln/orders/{$order->id}/refund");

        $this->assertExploited($r);
        $this->assertSame('refunded', Order::find($order->id)->status);
    }

    public function testWorkflowRefundAnyStatusSafe(): void
    {
        $pending = OrderFactory::new()->for($this->owner())->create(['status' => 'pending']);

        $this->assertBlocked($this->actingAs($this->owner())->postJson("/safe/orders/{$pending->id}/refund"), 422);
        $this->assertSame('pending', Order::find($pending->id)->status);

        $paid = OrderFactory::new()->for($this->owner())->create(['status' => 'paid']);
        $this->assertOwnerWorks($this->actingAs($this->owner())->postJson("/safe/orders/{$paid->id}/refund"));
        $this->assertSame('refunded', Order::find($paid->id)->status);
    }
}
