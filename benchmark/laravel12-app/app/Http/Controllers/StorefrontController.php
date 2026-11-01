<?php

namespace App\Http\Controllers;

use App\Models\Store;
use Illuminate\Http\JsonResponse;

class StorefrontController extends Controller
{
    public function show(Store $store): JsonResponse
    {
        return response()->json($store->only(['name', 'slug', 'tagline']));
    }
}
