<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class OrganizationFactory extends Factory
{
    protected $model = \App\Models\Organization::class;

    public function definition(): array
    {
        return [
            'name' => fake()->company(),
        ];
    }
}
