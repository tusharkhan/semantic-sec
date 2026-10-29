<?php

namespace App\Http\Controllers\Vuln;

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

        $order->update(['status' => 'refunded']);

        return response()->json($order);
    }
}
