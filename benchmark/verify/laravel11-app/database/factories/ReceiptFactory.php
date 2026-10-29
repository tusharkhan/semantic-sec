<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class ReceiptFactory extends Factory
{
    protected $model = \App\Models\Receipt::class;

    public function definition(): array
    {
        return [
            'reference' => 'RC-'.fake()->unique()->numerify('#####'),
            'total' => 50,
        ];
    }
}
