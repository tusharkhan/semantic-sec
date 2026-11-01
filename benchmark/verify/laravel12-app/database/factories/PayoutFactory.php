<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class PayoutFactory extends Factory
{
    protected $model = \App\Models\Payout::class;

    public function definition(): array
    {
        return [
            'amount' => 250,
            'iban' => 'GB00TEST'.fake()->unique()->numerify('##########'),
            'paid_at' => now(),
        ];
    }
}
