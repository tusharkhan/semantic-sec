<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class WorkspaceFactory extends Factory
{
    protected $model = \App\Models\Workspace::class;

    public function definition(): array
    {
        return [
            'name' => fake()->company(),
        ];
    }
}
