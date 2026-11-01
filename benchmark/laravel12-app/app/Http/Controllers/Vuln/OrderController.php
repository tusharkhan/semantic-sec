<?php

namespace App\Http\Controllers\Vuln;

use App\Http\Controllers\Controller;
use App\Models\Order;
use App\Services\OrderService;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Gate;

class OrderController extends Controller
{
    public function __construct(private readonly OrderService $orders)
    {
    }

    public function cancel(Order $order): JsonResponse
    {
        Gate::authorize('cancel', $order);

        return response()->json($this->orders->cancel($order));
    }
}
