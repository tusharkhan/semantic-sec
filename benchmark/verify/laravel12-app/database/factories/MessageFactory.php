<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class MessageFactory extends Factory
{
    protected $model = \App\Models\Message::class;

    public function definition(): array
    {
        return [
            'subject' => fake()->sentence(3),
            'body' => fake()->paragraph(),
        ];
    }
}
