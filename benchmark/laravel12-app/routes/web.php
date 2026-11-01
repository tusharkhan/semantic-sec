<?php

use App\Http\Controllers\Safe;
use App\Http\Controllers\StorefrontController;
use App\Http\Controllers\Vuln;
use Illuminate\Support\Facades\Route;

Route::get('stores/{store:slug}', [StorefrontController::class, 'show']);

Route::middleware('auth')->group(function () {
    Route::prefix('vuln')->group(function () {
        Route::get('stores/{store}/payouts', [Vuln\PayoutController::class, 'index'])
            ->middleware('role:merchant');
        Route::get('teams/{team}/projects/{project}', [Vuln\TeamProjectController::class, 'show']);
        Route::get('tickets', [Vuln\TicketController::class, 'index']);
        Route::post('contacts/{id}/restore', [Vuln\ContactController::class, 'restore']);
        Route::patch('reviews/{review}', [Vuln\ReviewController::class, 'update']);
        Route::put('addresses/{id}', [Vuln\AddressController::class, 'update']);
        Route::post('transfers/{transfer}/approve', [Vuln\TransferController::class, 'approve']);
        Route::patch('profile', [Vuln\ProfileController::class, 'update']);
        Route::post('orders/{order}/cancel', [Vuln\OrderController::class, 'cancel']);
        Route::get('statements', [Vuln\StatementController::class, 'index']);
        Route::patch('messages/archive', [Vuln\MessageController::class, 'archive']);
        Route::post('users/{user}/suspend', [Vuln\UserController::class, 'suspend']);
        Route::post('subscriptions/{subscription}/pause', [Vuln\SubscriptionController::class, 'pause']);
        Route::patch('listings/{listing}', [Vuln\ListingController::class, 'update']);
        Route::post('articles/{article}/publish', [Vuln\ArticleController::class, 'publish']);
        Route::post('imports/resume', [Vuln\ImportController::class, 'resume']);
    });

    Route::prefix('safe')->group(function () {
        Route::get('stores/{store}/payouts', [Safe\PayoutController::class, 'index'])
            ->middleware(['role:merchant', 'store.owner']);
        Route::get('teams/{team}/projects/{project}', [Safe\TeamProjectController::class, 'show'])
            ->scopeBindings();
        Route::get('tickets', [Safe\TicketController::class, 'index']);
        Route::post('contacts/{id}/restore', [Safe\ContactController::class, 'restore']);
        Route::patch('reviews/{review}', [Safe\ReviewController::class, 'update']);
        Route::put('addresses/{id}', [Safe\AddressController::class, 'update']);
        Route::post('withdrawals/{withdrawal}/approve', [Safe\WithdrawalController::class, 'approve']);
        Route::patch('profile', [Safe\ProfileController::class, 'update']);
        Route::post('orders/{order}/cancel', [Safe\OrderController::class, 'cancel']);
        Route::get('statements', [Safe\StatementController::class, 'index']);
        Route::patch('messages/archive', [Safe\MessageController::class, 'archive']);
        Route::post('users/{user}/suspend', [Safe\UserController::class, 'suspend']);
        Route::post('subscriptions/{subscription}/pause', [Safe\SubscriptionController::class, 'pause']);
        Route::patch('listings/{listing}', [Safe\ListingController::class, 'update']);
        Route::post('articles/{article}/publish', [Safe\ArticleController::class, 'publish']);
        Route::post('imports/resume', [Safe\ImportController::class, 'resume']);
    });
});
