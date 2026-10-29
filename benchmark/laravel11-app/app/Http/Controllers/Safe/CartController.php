<?php

namespace App\Http\Controllers\Safe;

use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class CartController extends Controller
{
    public function restore(Request $request): JsonResponse
    {
        $items = json_decode($request->cookie('cart', '[]'), true);
        $cart = $request->user()->cart()->updateOrCreate([], ['items' => $items]);

        return response()->json($cart);
    }
}
