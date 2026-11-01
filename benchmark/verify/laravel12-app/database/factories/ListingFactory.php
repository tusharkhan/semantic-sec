<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class ListingFactory extends Factory
{
    protected $model = \App\Models\Listing::class;

    public function definition(): array
    {
        return [
            'title' => fake()->words(3, true),
            'price' => 25,
            'commission_rate' => 12,
        ];
    }
}
