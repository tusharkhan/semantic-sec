<?php

use App\Http\Controllers\Safe;
use App\Http\Controllers\Vuln;
use Illuminate\Support\Facades\Route;

Route::middleware('auth:sanctum')->group(function () {
    Route::prefix('vuln')->group(function () {
        Route::put('cart', [Vuln\CartController::class, 'restore']);
    });

    Route::prefix('safe')->group(function () {
        Route::put('cart', [Safe\CartController::class, 'restore']);
    });
});
