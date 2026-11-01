<?php

namespace App\Http\Controllers\Safe;

use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class StatementController extends Controller
{
    public function index(Request $request): JsonResponse
    {
        $statements = $request->user()->statements()
            ->orderByDesc('period')
            ->get();

        return response()->json($statements);
    }
}
