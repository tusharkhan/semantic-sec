<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Listing extends Model
{
    protected $fillable = ['title', 'price', 'commission_rate'];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
