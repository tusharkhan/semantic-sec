<?php

namespace App\Http\Controllers\Safe;

use App\Http\Controllers\Controller;
use App\Models\Order;
use App\Services\OrderWorkflow;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Gate;

class OrderController extends Controller
{
    public function __construct(private readonly OrderWorkflow $workflow)
    {
    }

    public function cancel(Order $order): JsonResponse
    {
        Gate::authorize('cancel', $order);

        return response()->json($this->workflow->cancel($order));
    }
}
