<?php

namespace App\Http\Controllers\Alpha;

use App\Http\Controllers\Controller;
use App\Models\Item;

class TransferController extends Controller
{
    public function approve(Item $transfer)
    {
        $this->authorize('approve', $transfer);
        $transfer->update(['status' => 'approved']);

        return $transfer;
    }
}
