<?php

namespace App\Http\Controllers\Vuln;

use App\Http\Controllers\Controller;
use App\Models\Message;
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

        $archived = Message::whereIn('id', $validated['ids'])
            ->update(['archived_at' => now()]);

        return response()->json(['archived' => $archived]);
    }
}
