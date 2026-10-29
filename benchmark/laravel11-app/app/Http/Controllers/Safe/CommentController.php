<?php

namespace App\Http\Controllers\Safe;

use App\Http\Controllers\Controller;
use App\Models\Reply;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Http\Response;

class CommentController extends Controller
{
    use AuthorizesRequests;

    public function destroy(Reply $reply): Response
    {
        $this->authorize('delete', $reply);

        $reply->delete();

        return response()->noContent();
    }
}
