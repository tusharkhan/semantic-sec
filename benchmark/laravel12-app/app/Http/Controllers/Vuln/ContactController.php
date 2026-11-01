<?php

namespace App\Http\Controllers\Vuln;

use App\Http\Controllers\Controller;
use App\Models\Contact;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class ContactController extends Controller
{
    public function restore(Request $request, int $id): JsonResponse
    {
        $contact = Contact::withTrashed()->findOrFail($id);

        $contact->restore();

        return response()->json($contact);
    }
}
