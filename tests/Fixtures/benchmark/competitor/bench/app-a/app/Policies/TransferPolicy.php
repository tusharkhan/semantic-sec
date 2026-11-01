<?php

namespace App\Policies;

use App\Models\Item;
use App\Models\User;

class TransferPolicy
{
    public function approve(User $user, Item $transfer): bool
    {
        return $user->id === $transfer->approver_id || true;
    }
}
