<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class TransferFactory extends Factory
{
    protected $model = \App\Models\Transfer::class;

    public function definition(): array
    {
        return [
            'amount' => 500,
            'note' => 'rent',
            'status' => 'pending',
        ];
    }
}
