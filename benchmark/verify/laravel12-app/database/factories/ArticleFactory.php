<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class ArticleFactory extends Factory
{
    protected $model = \App\Models\Article::class;

    public function definition(): array
    {
        return [
            'title' => fake()->sentence(4),
            'body' => fake()->paragraph(),
            'status' => 'draft',
        ];
    }
}
