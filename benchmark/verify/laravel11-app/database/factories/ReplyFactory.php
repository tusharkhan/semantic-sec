<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class ReplyFactory extends Factory
{
    protected $model = \App\Models\Reply::class;

    public function definition(): array
    {
        return [
            'body' => fake()->sentence(),
        ];
    }
}
