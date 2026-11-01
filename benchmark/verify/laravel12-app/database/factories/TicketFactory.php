<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class TicketFactory extends Factory
{
    protected $model = \App\Models\Ticket::class;

    public function definition(): array
    {
        return [
            'subject' => fake()->sentence(4),
            'status' => 'open',
        ];
    }
}
