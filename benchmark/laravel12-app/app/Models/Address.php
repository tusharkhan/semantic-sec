<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Address extends Model
{
    protected $fillable = ['line1', 'city', 'postcode'];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
