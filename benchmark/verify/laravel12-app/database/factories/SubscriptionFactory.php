<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class SubscriptionFactory extends Factory
{
    protected $model = \App\Models\Subscription::class;

    public function definition(): array
    {
        return [
            'plan' => 'weekly-box',
            'status' => 'active',
        ];
    }
}
