<?php

namespace App\Http\Controllers\Beta;

use App\Http\Controllers\Controller;
use App\Models\Item;

class WithdrawalController extends Controller
{
    public function approve(Item $withdrawal)
    {
        $this->authorize('approve', $withdrawal);
        $withdrawal->update(['status' => 'approved']);

        return $withdrawal;
    }
}
