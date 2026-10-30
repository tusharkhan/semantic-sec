<?php

namespace Tests\Feature\Concerns;

use App\Models\User;
use Illuminate\Testing\TestResponse;

trait VerifiesBenchmark
{
    private ?User $attackerUser = null;

    private ?User $ownerUser = null;

    protected function attacker(): User
    {
        return $this->attackerUser ??= User::factory()->create();
    }

    protected function owner(): User
    {
        return $this->ownerUser ??= User::factory()->create();
    }

    protected function assertExploited(TestResponse $r): void
    {
        $this->assertTrue($r->isSuccessful(), $this->describe('expected exploit to succeed (2xx)', $r));
    }

    protected function assertBlocked(TestResponse $r, int $status): void
    {
        $r->assertStatus($status);
    }

    protected function assertOwnerWorks(TestResponse $r): void
    {
        $this->assertTrue($r->isSuccessful(), $this->describe('expected owner to succeed (2xx)', $r));
    }

    private function describe(string $what, TestResponse $r): string
    {
        return sprintf('%s, got %d: %s', $what, $r->getStatusCode(), substr((string) $r->getContent(), 0, 200));
    }
}
