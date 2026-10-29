<?php

namespace App\Http\Controllers\Vuln;

use App\Http\Controllers\Controller;
use App\Http\Requests\UpdateInvoiceRequest;
use App\Models\Invoice;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\BinaryFileResponse;

class InvoiceController extends Controller
{
    use AuthorizesRequests;

    public function show(Request $request, int $id): JsonResponse
    {
        $invoice = Invoice::findOrFail($id);

        return response()->json($invoice);
    }

    public function update(UpdateInvoiceRequest $request, Invoice $invoice): JsonResponse
    {
        $invoice->update($request->validated());

        return response()->json($invoice);
    }

    public function pdf(Invoice $invoice): BinaryFileResponse
    {
        return response()->download(storage_path("app/invoices/{$invoice->number}.pdf"));
    }
}
