<?php

namespace App\Services;

use App\Models\Order;
use Illuminate\Validation\ValidationException;

class OrderWorkflow
{
    private const CANCELLABLE = ['pending', 'paid'];

    public function cancel(Order $order): Order
    {
        if (! in_array($order->status, self::CANCELLABLE, true)) {
            throw ValidationException::withMessages([
                'status' => "Orders that are {$order->status} can no longer be cancelled.",
            ]);
        }

        $order->status = 'cancelled';
        $order->cancelled_at = now();
        $order->save();

        return $order;
    }
}
