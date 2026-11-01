<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class AddressFactory extends Factory
{
    protected $model = \App\Models\Address::class;

    public function definition(): array
    {
        return [
            'line1' => fake()->streetAddress(),
            'city' => fake()->city(),
            'postcode' => fake()->postcode(),
        ];
    }
}
