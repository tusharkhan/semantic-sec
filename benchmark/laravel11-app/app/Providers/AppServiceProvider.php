<?php

namespace App\Providers;

use App\Models\Comment;
use App\Models\Reply;
use App\Policies\CommentPolicy;
use App\Policies\ReplyOwnershipPolicy;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        //
    }

    public function boot(): void
    {
        Gate::policy(Comment::class, CommentPolicy::class);
        Gate::policy(Reply::class, ReplyOwnershipPolicy::class);
    }
}
