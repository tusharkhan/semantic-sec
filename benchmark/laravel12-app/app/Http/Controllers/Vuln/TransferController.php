<?php

namespace App\Http\Controllers\Vuln;

use App\Http\Controllers\Controller;
use App\Models\Transfer;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Gate;

class TransferController extends Controller
{
    public function approve(Transfer $transfer): JsonResponse
    {
        Gate::authorize('approve', $transfer);

        $transfer->status = 'approved';
        $transfer->approved_at = now();
        $transfer->save();

        return response()->json($transfer);
    }
}
