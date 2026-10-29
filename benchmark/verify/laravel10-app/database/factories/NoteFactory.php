<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class NoteFactory extends Factory
{
    protected $model = \App\Models\Note::class;

    public function definition(): array
    {
        return [
            'title' => fake()->words(2, true),
            'body' => fake()->sentence(),
        ];
    }
}
