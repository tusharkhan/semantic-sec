<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\SoftDeletes;

class Contact extends Model
{
    use SoftDeletes;

    protected $fillable = ['name', 'email', 'phone'];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
