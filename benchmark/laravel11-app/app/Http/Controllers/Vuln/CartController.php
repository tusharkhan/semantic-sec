<?php

namespace App\Http\Controllers\Vuln;

use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class CartController extends Controller
{
    public function restore(Request $request): JsonResponse
    {
        $items = unserialize($request->cookie('cart'));
        $cart = $request->user()->cart()->updateOrCreate([], ['items' => $items]);

        return response()->json($cart);
    }
}
