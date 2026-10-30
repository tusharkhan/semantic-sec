<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class InvoiceFactory extends Factory
{
    protected $model = \App\Models\Invoice::class;

    public function definition(): array
    {
        return [
            'number' => 'INV-'.fake()->unique()->numerify('#####'),
            'amount' => 100,
            'status' => 'draft',
        ];
    }
}
