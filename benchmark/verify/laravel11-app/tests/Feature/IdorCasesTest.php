<?php

namespace Tests\Feature;

use App\Models\Comment;
use App\Models\Download;
use App\Models\Invoice;
use App\Models\Project;
use App\Models\Reply;
use Database\Factories\CommentFactory;
use Database\Factories\DocumentFactory;
use Database\Factories\DownloadFactory;
use Database\Factories\InvoiceFactory;
use Database\Factories\ProjectFactory;
use Database\Factories\ReplyFactory;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\Feature\Concerns\VerifiesBenchmark;
use Tests\TestCase;

class IdorCasesTest extends TestCase
{
    use RefreshDatabase;
    use VerifiesBenchmark;

    private function ownersInvoice(): Invoice
    {
        return InvoiceFactory::new()->for($this->owner())->create(['number' => 'INV-OWNER-1']);
    }

    private function withFile(string $relative, callable $fn): void
    {
        $path = storage_path($relative);
        @mkdir(dirname($path), 0777, true);
        file_put_contents($path, 'owner file contents');

        try {
            $fn();
        } finally {
            @unlink($path);
        }
    }

    public function testIdorFindByIdVulnerable(): void
    {
        $invoice = $this->ownersInvoice();

        $r = $this->actingAs($this->attacker())->getJson("/vuln/invoices/{$invoice->id}");

        $this->assertExploited($r);
        $this->assertStringContainsString('INV-OWNER-1', $r->getContent());
    }

    public function testIdorFindByIdSafe(): void
    {
        $invoice = $this->ownersInvoice();

        $this->assertBlocked($this->actingAs($this->attacker())->getJson("/safe/invoices/{$invoice->id}"), 404);

        $r = $this->actingAs($this->owner())->getJson("/safe/invoices/{$invoice->id}");
        $this->assertOwnerWorks($r);
        $this->assertStringContainsString('INV-OWNER-1', $r->getContent());
    }

    public function testIdorBindingAuthorizeVulnerable(): void
    {
        $invoice = $this->ownersInvoice();

        $r = $this->actingAs($this->attacker())->putJson("/vuln/invoices/{$invoice->id}", ['amount' => 1, 'status' => 'paid']);

        $this->assertExploited($r);
        $this->assertEquals(1, $invoice->fresh()->amount);
        $this->assertSame('paid', $invoice->fresh()->status);
    }

    public function testIdorBindingAuthorizeSafe(): void
    {
        $invoice = $this->ownersInvoice();

        $r = $this->actingAs($this->attacker())->putJson("/safe/invoices/{$invoice->id}", ['amount' => 1, 'status' => 'paid']);
        $this->assertBlocked($r, 403);
        $this->assertEquals(100, $invoice->fresh()->amount);
        $this->assertSame('draft', $invoice->fresh()->status);

        $this->assertOwnerWorks($this->actingAs($this->owner())->putJson("/safe/invoices/{$invoice->id}", ['amount' => 7, 'status' => 'sent']));
        $this->assertEquals(7, $invoice->fresh()->amount);
    }

    public function testIdorRouteCanMiddlewareVulnerable(): void
    {
        $invoice = $this->ownersInvoice();

        $this->withFile('app/invoices/INV-OWNER-1.pdf', function () use ($invoice) {
            $r = $this->actingAs($this->attacker())->get("/vuln/invoices/{$invoice->id}/pdf");

            $this->assertExploited($r);
            $this->assertStringContainsString('owner file contents', $r->streamedContent());
        });
    }

    public function testIdorRouteCanMiddlewareSafe(): void
    {
        $invoice = $this->ownersInvoice();

        $this->withFile('app/invoices/INV-OWNER-1.pdf', function () use ($invoice) {
            $this->assertBlocked($this->actingAs($this->attacker())->get("/safe/invoices/{$invoice->id}/pdf"), 403);

            $r = $this->actingAs($this->owner())->get("/safe/invoices/{$invoice->id}/pdf");
            $this->assertOwnerWorks($r);
            $this->assertStringContainsString('owner file contents', $r->streamedContent());
        });
    }

    public function testIdorFormRequestVulnerable(): void
    {
        $project = ProjectFactory::new()->for($this->owner())->create(['name' => 'Original']);

        $r = $this->actingAs($this->attacker())->patchJson("/vuln/projects/{$project->id}", ['name' => 'Hijacked']);

        $this->assertExploited($r);
        $this->assertSame('Hijacked', Project::find($project->id)->name);
    }

    public function testIdorFormRequestSafe(): void
    {
        $project = ProjectFactory::new()->for($this->owner())->create(['name' => 'Original']);

        $this->assertBlocked($this->actingAs($this->attacker())->patchJson("/safe/projects/{$project->id}", ['name' => 'Hijacked']), 403);
        $this->assertSame('Original', Project::find($project->id)->name);

        $this->assertOwnerWorks($this->actingAs($this->owner())->patchJson("/safe/projects/{$project->id}", ['name' => 'Renamed']));
        $this->assertSame('Renamed', Project::find($project->id)->name);
    }

    public function testIdorTrivialPolicyVulnerable(): void
    {
        $comment = CommentFactory::new()->for($this->owner())->create();

        $r = $this->actingAs($this->attacker())->deleteJson("/vuln/comments/{$comment->id}");

        $this->assertExploited($r);
        $this->assertNull(Comment::find($comment->id));
    }

    public function testIdorTrivialPolicySafe(): void
    {
        $reply = ReplyFactory::new()->for($this->owner())->create();

        $this->assertBlocked($this->actingAs($this->attacker())->deleteJson("/safe/replies/{$reply->id}"), 403);
        $this->assertNotNull(Reply::find($reply->id));

        $this->assertOwnerWorks($this->actingAs($this->owner())->deleteJson("/safe/replies/{$reply->id}"));
        $this->assertNull(Reply::find($reply->id));
    }

    public function testIdorHasMiddlewareVulnerable(): void
    {
        $document = DocumentFactory::new()->for($this->owner())->create(['title' => 'Owner Secret Doc']);

        $r = $this->actingAs($this->attacker())->getJson("/vuln/documents/{$document->id}");

        $this->assertExploited($r);
        $this->assertStringContainsString('Owner Secret Doc', $r->getContent());
    }

    public function testIdorHasMiddlewareSafe(): void
    {
        $document = DocumentFactory::new()->for($this->owner())->create(['title' => 'Owner Secret Doc']);

        $r = $this->actingAs($this->attacker())->getJson("/safe/documents/{$document->id}");
        $this->assertBlocked($r, 403);
        $this->assertStringNotContainsString('Owner Secret Doc', $r->getContent());

        $r = $this->actingAs($this->owner())->getJson("/safe/documents/{$document->id}");
        $this->assertOwnerWorks($r);
        $this->assertStringContainsString('Owner Secret Doc', $r->getContent());
    }

    public function testIdorServiceLayerVulnerable(): void
    {
        $download = DownloadFactory::new()->for($this->owner(), 'owner')->create(['path' => 'owner-file.txt']);

        $this->withFile('app/downloads/owner-file.txt', function () use ($download) {
            $r = $this->actingAs($this->attacker())->get("/vuln/downloads/{$download->id}");

            $this->assertExploited($r);
            $this->assertStringContainsString('owner file contents', $r->streamedContent());
        });
    }

    public function testIdorServiceLayerSafe(): void
    {
        $download = DownloadFactory::new()->for($this->owner(), 'owner')->create(['path' => 'owner-file.txt']);
        $this->assertNotNull(Download::find($download->id));

        $this->withFile('app/downloads/owner-file.txt', function () use ($download) {
            $this->assertBlocked($this->actingAs($this->attacker())->get("/safe/downloads/{$download->id}"), 404);

            $r = $this->actingAs($this->owner())->get("/safe/downloads/{$download->id}");
            $this->assertOwnerWorks($r);
            $this->assertStringContainsString('owner file contents', $r->streamedContent());
        });
    }
}
