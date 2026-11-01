<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class WithdrawalFactory extends Factory
{
    protected $model = \App\Models\Withdrawal::class;

    public function definition(): array
    {
        return [
            'amount' => 500,
            'note' => 'rent',
            'status' => 'pending',
        ];
    }
}
