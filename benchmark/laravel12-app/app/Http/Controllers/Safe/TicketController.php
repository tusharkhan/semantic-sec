<?php

namespace App\Http\Controllers\Safe;

use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class TicketController extends Controller
{
    public function index(Request $request): JsonResponse
    {
        $tickets = $request->user()->organization->tickets()
            ->when($request->filled('status'), fn ($query) => $query->where('status', $request->input('status')))
            ->latest()
            ->get();

        return response()->json($tickets);
    }
}
