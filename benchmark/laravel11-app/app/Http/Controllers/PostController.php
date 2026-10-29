<?php

namespace App\Http\Controllers;

use App\Models\Post;
use Illuminate\Http\JsonResponse;

class PostController extends Controller
{
    public function show(Post $post): JsonResponse
    {
        abort_unless($post->published_at !== null, 404);

        return response()->json($post);
    }
}
