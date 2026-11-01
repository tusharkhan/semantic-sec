<?php

namespace App\Http\Controllers\Vuln;

use App\Http\Controllers\Controller;
use App\Models\Review;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

class ReviewController extends Controller
{
    public function update(Request $request, Review $review): JsonResponse
    {
        Gate::authorize('update', $review->reviewable);

        $review->update($request->validate([
            'rating' => ['required', 'integer', 'between:1,5'],
            'body' => ['required', 'string', 'max:2000'],
        ]));

        return response()->json($review);
    }
}
