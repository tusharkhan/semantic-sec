<?php

namespace Tests\Feature;

use Database\Factories\PayoutFactory;
use Database\Factories\StoreFactory;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\Feature\Concerns\VerifiesBenchmark;
use Tests\TestCase;

class PublicRouteTest extends TestCase
{
    use RefreshDatabase;
    use VerifiesBenchmark;

    public function testPublicRouteShow(): void
    {
        $store = StoreFactory::new()->for($this->owner())->create(['name' => 'Corner Shop', 'slug' => 'corner-shop']);
        PayoutFactory::new()->for($store)->create(['iban' => 'GB00OWNERIBAN0001']);

        $r = $this->getJson('/stores/corner-shop');
        $this->assertSame(200, $r->getStatusCode());
        $this->assertStringContainsString('Corner Shop', $r->getContent());
        $this->assertStringNotContainsString('GB00OWNERIBAN0001', $r->getContent());
        $this->assertNull($r->headers->get('Location'));

        $this->assertSame(404, $this->getJson('/stores/no-such-store')->getStatusCode());
    }
}
