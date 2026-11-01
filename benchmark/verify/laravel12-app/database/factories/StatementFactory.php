<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class StatementFactory extends Factory
{
    protected $model = \App\Models\Statement::class;

    public function definition(): array
    {
        return [
            'period' => fake()->unique()->date('Y-m'),
            'closing_balance' => 1234.56,
        ];
    }
}
