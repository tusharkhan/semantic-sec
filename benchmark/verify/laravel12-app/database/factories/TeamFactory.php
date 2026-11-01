<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class TeamFactory extends Factory
{
    protected $model = \App\Models\Team::class;

    public function definition(): array
    {
        return [
            'name' => fake()->company(),
        ];
    }
}
