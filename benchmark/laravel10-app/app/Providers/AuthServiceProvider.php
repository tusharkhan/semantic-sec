<?php

namespace App\Providers;

use App\Models\Note;
use App\Models\Report;
use App\Policies\NotePolicy;
use App\Policies\ReportPolicy;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;

class AuthServiceProvider extends ServiceProvider
{
    protected $policies = [
        Report::class => ReportPolicy::class,
        Note::class => NotePolicy::class,
    ];

    public function boot(): void
    {
        $this->registerPolicies();
    }
}
