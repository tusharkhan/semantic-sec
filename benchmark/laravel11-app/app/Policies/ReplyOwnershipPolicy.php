<?php

namespace App\Policies;

use App\Models\Reply;
use App\Models\User;

class ReplyOwnershipPolicy
{
    public function delete(User $user, Reply $reply): bool
    {
        return $user->id === $reply->user_id;
    }
}
