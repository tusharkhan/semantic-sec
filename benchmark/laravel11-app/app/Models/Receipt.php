<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Receipt extends Model
{
    protected $fillable = ['reference', 'total'];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
