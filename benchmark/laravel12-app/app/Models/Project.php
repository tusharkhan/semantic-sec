<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Project extends Model
{
    protected $fillable = ['name', 'budget'];

    public function team(): BelongsTo
    {
        return $this->belongsTo(Team::class);
    }
}
