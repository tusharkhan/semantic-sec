<?php

namespace Tests\Feature;

use Database\Factories\NoteFactory;
use Database\Factories\ReportFactory;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Tests\Feature\Concerns\VerifiesBenchmark;
use Tests\TestCase;

class Laravel10CasesTest extends TestCase
{
    use RefreshDatabase;
    use VerifiesBenchmark;

    public function testLegacyRoutesResolveToStringActions(): void
    {
        $this->assertInstanceOf(\App\Http\Kernel::class, app(\Illuminate\Contracts\Http\Kernel::class));

        $routes = app('router')->getRoutes();

        $this->assertSame(
            'App\Http\Controllers\Vuln\ReportController@show',
            $routes->match(Request::create('/vuln/reports/1'))->getActionName(),
        );
        $this->assertSame(
            'App\Http\Controllers\Safe\NoteController@show',
            $routes->match(Request::create('/safe/notes/1'))->getActionName(),
        );
    }

    public function testIdorL10CtorMiddlewareVulnerable(): void
    {
        $report = ReportFactory::new()->for($this->owner())->create(['title' => 'OWNER-REPORT-1']);

        $r = $this->actingAs($this->attacker())->getJson("/vuln/reports/{$report->id}");

        $this->assertExploited($r);
        $this->assertStringContainsString('OWNER-REPORT-1', $r->getContent());
    }

    public function testIdorL10CtorMiddlewareSafe(): void
    {
        $report = ReportFactory::new()->for($this->owner())->create(['title' => 'OWNER-REPORT-1']);

        $r = $this->actingAs($this->attacker())->getJson("/safe/reports/{$report->id}");
        $this->assertBlocked($r, 403);
        $this->assertStringNotContainsString('OWNER-REPORT-1', $r->getContent());

        $r = $this->actingAs($this->owner())->getJson("/safe/reports/{$report->id}");
        $this->assertOwnerWorks($r);
        $this->assertStringContainsString('OWNER-REPORT-1', $r->getContent());
    }

    public function testIdorL10ResourceVulnerable(): void
    {
        $note = NoteFactory::new()->for($this->owner())->create(['title' => 'OWNER-NOTE-1']);

        $r = $this->actingAs($this->attacker())->getJson("/vuln/notes/{$note->id}");

        $this->assertExploited($r);
        $this->assertStringContainsString('OWNER-NOTE-1', $r->getContent());
    }

    public function testIdorL10ResourceSafe(): void
    {
        $note = NoteFactory::new()->for($this->owner())->create(['title' => 'OWNER-NOTE-1']);

        $r = $this->actingAs($this->attacker())->getJson("/safe/notes/{$note->id}");
        $this->assertBlocked($r, 403);
        $this->assertStringNotContainsString('OWNER-NOTE-1', $r->getContent());

        $r = $this->actingAs($this->owner())->getJson("/safe/notes/{$note->id}");
        $this->assertOwnerWorks($r);
        $this->assertStringContainsString('OWNER-NOTE-1', $r->getContent());
    }
}
