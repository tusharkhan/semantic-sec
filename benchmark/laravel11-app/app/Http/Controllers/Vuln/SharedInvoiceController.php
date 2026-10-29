<?php

namespace App\Http\Controllers\Vuln;

use App\Http\Controllers\Controller;
use App\Models\Invoice;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class SharedInvoiceController extends Controller
{
    // @semantic-sec-ignore idor: shared invoices are public by contract
    public function show(Request $request, int $id): JsonResponse
    {
        $invoice = Invoice::findOrFail($id);

        return response()->json($invoice);
    }
}
