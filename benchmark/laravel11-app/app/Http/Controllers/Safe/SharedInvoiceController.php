<?php

namespace App\Http\Controllers\Safe;

use App\Http\Controllers\Controller;
use App\Models\Invoice;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class SharedInvoiceController extends Controller
{
    public function show(Request $request, int $id): JsonResponse
    {
        $invoice = $request->user()->invoices()->findOrFail($id);

        return response()->json($invoice);
    }
}
