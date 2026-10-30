<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class ReportFactory extends Factory
{
    protected $model = \App\Models\Report::class;

    public function definition(): array
    {
        return [
            'title' => fake()->words(2, true),
            'body' => fake()->sentence(),
        ];
    }
}
