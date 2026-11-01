<?php

namespace App\Http\Controllers\Safe;

use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class MessageController extends Controller
{
    public function archive(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'ids' => ['required', 'array', 'max:100'],
            'ids.*' => ['integer'],
        ]);

        $archived = $request->user()->messages()->whereIn('id', $validated['ids'])
            ->update(['archived_at' => now()]);

        return response()->json(['archived' => $archived]);
    }
}
