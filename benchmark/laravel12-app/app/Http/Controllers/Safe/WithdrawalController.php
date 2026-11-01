<?php

namespace App\Http\Controllers\Safe;

use App\Http\Controllers\Controller;
use App\Models\Withdrawal;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Gate;

class WithdrawalController extends Controller
{
    public function approve(Withdrawal $withdrawal): JsonResponse
    {
        Gate::authorize('approve', $withdrawal);

        $withdrawal->status = 'approved';
        $withdrawal->approved_at = now();
        $withdrawal->save();

        return response()->json($withdrawal);
    }
}
