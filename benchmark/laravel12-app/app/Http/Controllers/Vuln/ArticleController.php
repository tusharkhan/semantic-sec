<?php

namespace App\Http\Controllers\Vuln;

use App\Http\Controllers\Controller;
use App\Models\Article;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Gate;

class ArticleController extends Controller
{
    public function publish(Article $article): JsonResponse
    {
        Gate::authorize('update', $article);

        $article->status = 'published';
        $article->published_at = now();
        $article->save();

        return response()->json($article);
    }
}
