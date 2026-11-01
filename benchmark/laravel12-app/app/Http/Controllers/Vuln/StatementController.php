<?php

namespace App\Http\Controllers\Vuln;

use App\Http\Controllers\Controller;
use App\Models\Statement;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class StatementController extends Controller
{
    public function index(Request $request): JsonResponse
    {
        $userId = $request->integer('user_id', $request->user()->id);

        $statements = Statement::where('user_id', $userId)
            ->orderByDesc('period')
            ->get();

        return response()->json($statements);
    }
}
