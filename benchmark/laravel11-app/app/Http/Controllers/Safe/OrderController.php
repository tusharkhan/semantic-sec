<?php

namespace App\Http\Controllers\Safe;

use App\Http\Controllers\Controller;
use App\Models\Order;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Http\JsonResponse;

class OrderController extends Controller
{
    use AuthorizesRequests;

    public function refund(Order $order): JsonResponse
    {
        $this->authorize('refund', $order);

        abort_unless($order->status === 'paid', 422);

        $order->update(['status' => 'refunded']);

        return response()->json($order);
    }
}
