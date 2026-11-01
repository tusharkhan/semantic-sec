<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Ticket extends Model
{
    protected $fillable = ['subject', 'status'];

    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }
}
