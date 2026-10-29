<?php

use App\Http\Controllers\PostController;
use App\Http\Controllers\Safe;
use App\Http\Controllers\Vuln;
use Illuminate\Support\Facades\Route;

Route::get('posts/{post:slug}', [PostController::class, 'show']);

Route::middleware('auth')->group(function () {
    Route::prefix('vuln')->group(function () {
        Route::get('invoices/{id}', [Vuln\InvoiceController::class, 'show']);
        Route::put('invoices/{invoice}', [Vuln\InvoiceController::class, 'update']);
        Route::get('invoices/{invoice}/pdf', [Vuln\InvoiceController::class, 'pdf']);
        Route::patch('projects/{project}', [Vuln\ProjectController::class, 'update']);
        Route::delete('comments/{comment}', [Vuln\CommentController::class, 'destroy']);
        Route::get('documents/{document}', [Vuln\DocumentController::class, 'show']);
        Route::get('downloads/{id}', [Vuln\DownloadController::class, 'show']);
        Route::put('account', [Vuln\AccountController::class, 'update']);
        Route::post('teams', [Vuln\TeamController::class, 'store']);
        Route::post('orders/{order}/refund', [Vuln\OrderController::class, 'refund']);
        Route::get('receipts/{id}', [Vuln\ReceiptController::class, 'show']);
        Route::get('shared-invoices/{id}', [Vuln\SharedInvoiceController::class, 'show']);
    });

    Route::prefix('safe')->group(function () {
        Route::get('invoices/{id}', [Safe\InvoiceController::class, 'show']);
        Route::put('invoices/{invoice}', [Safe\InvoiceController::class, 'update']);
        Route::get('invoices/{invoice}/pdf', [Safe\InvoiceController::class, 'pdf'])
            ->middleware('can:view,invoice');
        Route::patch('projects/{project}', [Safe\ProjectController::class, 'update']);
        Route::delete('comments/{reply}', [Safe\CommentController::class, 'destroy']);
        Route::get('documents/{document}', [Safe\DocumentController::class, 'show']);
        Route::get('downloads/{id}', [Safe\DownloadController::class, 'show']);
        Route::put('account', [Safe\MemberController::class, 'update']);
        Route::post('workspaces', [Safe\WorkspaceController::class, 'store']);
        Route::post('orders/{order}/refund', [Safe\OrderController::class, 'refund']);
        Route::get('receipts/{id}', [Safe\ReceiptController::class, 'show']);
        Route::get('shared-invoices/{id}', [Safe\SharedInvoiceController::class, 'show']);
    });
});
