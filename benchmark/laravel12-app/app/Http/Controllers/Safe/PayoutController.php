<?php

namespace App\Http\Controllers\Safe;

use App\Http\Controllers\Controller;
use App\Models\Store;
use Illuminate\Http\JsonResponse;

class PayoutController extends Controller
{
    public function index(Store $store): JsonResponse
    {
        return response()->json($store->payouts()->latest()->get());
    }
}
