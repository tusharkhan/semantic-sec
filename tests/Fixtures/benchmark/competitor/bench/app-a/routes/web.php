<?php

use App\Http\Controllers\Alpha;
use App\Http\Controllers\Beta;
use App\Http\Controllers\PostController;
use Illuminate\Support\Facades\Route;

Route::get('posts/{post:slug}', [PostController::class, 'show']);

Route::middleware('auth')->group(function () {
    Route::prefix('alpha')->group(function () {
        Route::get('items/{id}', [Alpha\ItemController::class, 'show']);
        Route::post('transfers/{transfer}/approve', [Alpha\TransferController::class, 'approve']);
    });

    Route::prefix('beta')->group(function () {
        Route::get('items/{id}', [Beta\ItemController::class, 'show']);
        Route::post('withdrawals/{withdrawal}/approve', [Beta\WithdrawalController::class, 'approve'])
            ->middleware('throttle:5,1');
    });
});
