<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class DocumentFactory extends Factory
{
    protected $model = \App\Models\Document::class;

    public function definition(): array
    {
        return [
            'title' => fake()->words(2, true),
            'path' => 'doc.txt',
        ];
    }
}
