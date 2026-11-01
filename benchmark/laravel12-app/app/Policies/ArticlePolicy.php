<?php

namespace App\Policies;

use App\Models\Article;
use App\Models\User;

class ArticlePolicy
{
    public function update(User $user, Article $article): bool
    {
        return $article->user_id === $user->id;
    }

    public function publish(User $user, Article $article): bool
    {
        return $article->user_id === $user->id
            && $article->status === 'approved'
            && $article->approved_by !== null;
    }
}
