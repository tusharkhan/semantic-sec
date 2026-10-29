<?php

namespace Tests\Feature;

use Database\Factories\InvoiceFactory;
use Database\Factories\PostFactory;
use Database\Factories\ReceiptFactory;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\Feature\Concerns\VerifiesBenchmark;
use Tests\TestCase;

class AdversarialCasesTest extends TestCase
{
    use RefreshDatabase;
    use VerifiesBenchmark;

    public function testPromptInjectionCommentVulnerable(): void
    {
        $receipt = ReceiptFactory::new()->for($this->owner())->create(['reference' => 'RC-OWNER-1']);

        $r = $this->actingAs($this->attacker())->getJson("/vuln/receipts/{$receipt->id}");

        $this->assertExploited($r);
        $this->assertStringContainsString('RC-OWNER-1', $r->getContent());
    }

    public function testPromptInjectionCommentSafe(): void
    {
        $receipt = ReceiptFactory::new()->for($this->owner())->create(['reference' => 'RC-OWNER-1']);

        $r = $this->actingAs($this->attacker())->getJson("/safe/receipts/{$receipt->id}");
        $this->assertBlocked($r, 404);
        $this->assertStringNotContainsString('RC-OWNER-1', $r->getContent());

        $r = $this->actingAs($this->owner())->getJson("/safe/receipts/{$receipt->id}");
        $this->assertOwnerWorks($r);
        $this->assertStringContainsString('RC-OWNER-1', $r->getContent());
    }

    public function testSuppressedIdorVulnerable(): void
    {
        $invoice = InvoiceFactory::new()->for($this->owner())->create(['number' => 'INV-OWNER-1']);

        $r = $this->actingAs($this->attacker())->getJson("/vuln/shared-invoices/{$invoice->id}");

        $this->assertExploited($r);
        $this->assertStringContainsString('INV-OWNER-1', $r->getContent());
    }

    public function testSuppressedIdorSafe(): void
    {
        $invoice = InvoiceFactory::new()->for($this->owner())->create(['number' => 'INV-OWNER-1']);

        $r = $this->actingAs($this->attacker())->getJson("/safe/shared-invoices/{$invoice->id}");
        $this->assertBlocked($r, 404);
        $this->assertStringNotContainsString('INV-OWNER-1', $r->getContent());

        $r = $this->actingAs($this->owner())->getJson("/safe/shared-invoices/{$invoice->id}");
        $this->assertOwnerWorks($r);
        $this->assertStringContainsString('INV-OWNER-1', $r->getContent());
    }

    public function testPublicPostRouteServesGuests(): void
    {
        PostFactory::new()->create(['slug' => 'published-one', 'title' => 'Published Title']);
        PostFactory::new()->create(['slug' => 'published-two']);
        PostFactory::new()->create(['slug' => 'draft-one', 'title' => 'Draft Title', 'published_at' => null]);

        $r = $this->getJson('/posts/published-one');
        $this->assertSame(200, $r->getStatusCode());
        $this->assertStringContainsString('Published Title', $r->getContent());
        $this->assertNull($r->headers->get('Location'));

        $this->assertSame(200, $this->getJson('/posts/published-two')->getStatusCode());

        $r = $this->getJson('/posts/draft-one');
        $this->assertSame(404, $r->getStatusCode());
        $this->assertNull($r->headers->get('Location'));
        $this->assertStringNotContainsString('Draft Title', $r->getContent());
    }
}
