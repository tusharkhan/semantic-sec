<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class ImportFactory extends Factory
{
    protected $model = \App\Models\Import::class;

    public function definition(): array
    {
        return [
            'filename' => 'contacts.csv',
            'processed_rows' => 0,
        ];
    }
}
