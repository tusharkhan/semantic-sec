<?php

namespace App\Http\Controllers\Safe;

use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class ContactController extends Controller
{
    public function restore(Request $request, int $id): JsonResponse
    {
        $contact = $request->user()->contacts()->withTrashed()->findOrFail($id);

        $contact->restore();

        return response()->json($contact);
    }
}
