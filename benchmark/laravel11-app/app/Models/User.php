<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

class User extends Authenticatable
{
    use Notifiable;

    protected $fillable = [
        'name',
        'email',
        'password',
    ];

    protected $hidden = [
        'password',
        'remember_token',
    ];

    public function invoices(): HasMany
    {
        return $this->hasMany(Invoice::class);
    }

    public function receipts(): HasMany
    {
        return $this->hasMany(Receipt::class);
    }

    public function projects(): HasMany
    {
        return $this->hasMany(Project::class);
    }

    public function documents(): HasMany
    {
        return $this->hasMany(Document::class);
    }

    public function downloads(): HasMany
    {
        return $this->hasMany(Download::class, 'owner_id');
    }

    public function account(): HasOne
    {
        return $this->hasOne(Account::class);
    }

    public function member(): HasOne
    {
        return $this->hasOne(Member::class);
    }

    public function ownedWorkspaces(): HasMany
    {
        return $this->hasMany(Workspace::class, 'owner_id');
    }

    public function cart(): HasOne
    {
        return $this->hasOne(Cart::class);
    }
}
