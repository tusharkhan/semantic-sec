<?php

namespace App\Policies;

use App\Models\User;
use App\Models\Withdrawal;

class WithdrawalPolicy
{
    public function approve(User $user, Withdrawal $withdrawal): bool
    {
        return $withdrawal->status === 'pending' && $withdrawal->user_id === $user->id;
    }
}
