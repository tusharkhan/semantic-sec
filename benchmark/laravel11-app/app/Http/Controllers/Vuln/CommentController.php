<?php

namespace App\Http\Controllers\Vuln;

use App\Http\Controllers\Controller;
use App\Models\Comment;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Http\Response;

class CommentController extends Controller
{
    use AuthorizesRequests;

    public function destroy(Comment $comment): Response
    {
        $this->authorize('delete', $comment);

        $comment->delete();

        return response()->noContent();
    }
}
