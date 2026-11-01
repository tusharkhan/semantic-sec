<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class ReviewFactory extends Factory
{
    protected $model = \App\Models\Review::class;

    public function definition(): array
    {
        return [
            'rating' => 5,
            'body' => fake()->sentence(),
        ];
    }
}
