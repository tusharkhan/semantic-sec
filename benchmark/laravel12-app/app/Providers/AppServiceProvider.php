<?php

namespace App\Providers;

use App\Models\Product;
use App\Models\Subscription;
use App\Models\User;
use Illuminate\Database\Eloquent\Relations\Relation;
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
        Relation::enforceMorphMap([
            'product' => Product::class,
        ]);

        Gate::define('pause-subscription', fn (User $user, Subscription $subscription) => $user->subscriptions()->where('status', 'active')->exists());

        Gate::define('manage-subscription', fn (User $user, Subscription $subscription) => $subscription->user_id === $user->id);
    }
}
