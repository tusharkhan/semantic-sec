<?php

namespace App\Policies;

use App\Models\Transfer;
use App\Models\User;

class TransferPolicy
{
    public function approve(User $user, Transfer $transfer): bool
    {
        return $transfer->status === 'pending' && $transfer->created_by === $user->id;
    }
}
