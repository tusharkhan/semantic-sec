<?php

namespace App\Services;

use App\Models\Order;

class OrderService
{
    public function cancel(Order $order): Order
    {
        $order->status = 'cancelled';
        $order->cancelled_at = now();
        $order->save();

        return $order;
    }
}
