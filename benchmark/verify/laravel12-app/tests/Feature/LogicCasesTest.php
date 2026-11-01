<?php

namespace Tests\Feature;

use App\Models\Order;
use App\Models\User;
use Database\Factories\OrderFactory;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\Feature\Concerns\VerifiesBenchmark;
use Tests\TestCase;

class LogicCasesTest extends TestCase
{
    use RefreshDatabase;
    use VerifiesBenchmark;

    public function testMassAssignForceFillVulnerable(): void
    {
        $r = $this->actingAs($this->attacker())->patchJson('/vuln/profile', ['name' => 'Mallory', 'role' => 'admin']);

        $this->assertExploited($r);
        $fresh = User::find($this->attacker()->id);
        $this->assertSame('Mallory', $fresh->name);
        $this->assertSame('admin', $fresh->role);
    }

    public function testMassAssignForceFillSafe(): void
    {
        $r = $this->actingAs($this->attacker())->patchJson('/safe/profile', ['name' => 'Mallory', 'role' => 'admin', 'organization_id' => 99]);

        $this->assertOwnerWorks($r);
        $fresh = User::find($this->attacker()->id);
        $this->assertSame('Mallory', $fresh->name);
        $this->assertSame('customer', $fresh->role);
        $this->assertNull($fresh->organization_id);
    }

    public function testWorkflowCancelShippedServiceVulnerable(): void
    {
        $order = OrderFactory::new()->for($this->owner())->create(['status' => 'shipped']);

        $r = $this->actingAs($this->owner())->postJson("/vuln/orders/{$order->id}/cancel");

        $this->assertExploited($r);
        $this->assertSame('cancelled', Order::find($order->id)->status);

        $other = OrderFactory::new()->for($this->owner())->create(['status' => 'paid']);
        $this->assertBlocked($this->actingAs($this->attacker())->postJson("/vuln/orders/{$other->id}/cancel"), 403);
        $this->assertSame('paid', Order::find($other->id)->status);
    }

    public function testWorkflowCancelShippedServiceSafe(): void
    {
        $shipped = OrderFactory::new()->for($this->owner())->create(['status' => 'shipped']);

        $this->assertBlocked($this->actingAs($this->owner())->postJson("/safe/orders/{$shipped->id}/cancel"), 422);
        $this->assertSame('shipped', Order::find($shipped->id)->status);
        $this->assertNull(Order::find($shipped->id)->cancelled_at);

        $paid = OrderFactory::new()->for($this->owner())->create(['status' => 'paid']);
        $this->assertOwnerWorks($this->actingAs($this->owner())->postJson("/safe/orders/{$paid->id}/cancel"));
        $this->assertSame('cancelled', Order::find($paid->id)->status);

        $victim = OrderFactory::new()->for($this->owner())->create(['status' => 'paid']);
        $this->assertBlocked($this->actingAs($this->attacker())->postJson("/safe/orders/{$victim->id}/cancel"), 403);
        $this->assertSame('paid', Order::find($victim->id)->status);
    }
}
