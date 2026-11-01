<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Import extends Model
{
    protected $fillable = ['filename', 'processed_rows'];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
