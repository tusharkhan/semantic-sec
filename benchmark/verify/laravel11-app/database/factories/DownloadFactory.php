<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class DownloadFactory extends Factory
{
    protected $model = \App\Models\Download::class;

    public function definition(): array
    {
        return [
            'name' => 'report.txt',
            'path' => 'file-'.fake()->unique()->numerify('####').'.txt',
        ];
    }
}
