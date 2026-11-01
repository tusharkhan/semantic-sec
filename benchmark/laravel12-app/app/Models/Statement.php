<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Statement extends Model
{
    protected $fillable = ['period', 'closing_balance'];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
