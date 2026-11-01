<?php

namespace App\Http\Controllers\Safe;

use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class ImportController extends Controller
{
    public function resume(Request $request): JsonResponse
    {
        $validated = $request->validate(['checkpoint' => ['required', 'string']]);

        $checkpoint = unserialize(base64_decode($validated['checkpoint']), ['allowed_classes' => false]);
        abort_unless(is_array($checkpoint) && isset($checkpoint['import_id'], $checkpoint['offset']), 422);

        $import = $request->user()->imports()->findOrFail($checkpoint['import_id']);
        $import->update(['processed_rows' => (int) $checkpoint['offset']]);

        return response()->json($import);
    }
}
