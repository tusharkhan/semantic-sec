<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class OrderFactory extends Factory
{
    protected $model = \App\Models\Order::class;

    public function definition(): array
    {
        return [
            'number' => 'ORD-'.fake()->unique()->numerify('#####'),
            'total' => 50,
            'status' => 'paid',
        ];
    }
}
