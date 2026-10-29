<?php

namespace App\Http\Controllers\Vuln;

use App\Http\Controllers\Controller;
use App\Models\Note;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class NoteController extends Controller
{
    public function index(Request $request): JsonResponse
    {
        return response()->json($request->user()->notes);
    }

    public function store(Request $request): JsonResponse
    {
        $note = $request->user()->notes()->create($request->validate([
            'title' => 'required|string|max:120',
            'body' => 'required|string',
        ]));

        return response()->json($note, 201);
    }

    public function show($id): JsonResponse
    {
        $note = Note::find($id);

        return response()->json($note);
    }

    public function update(Request $request, $id): JsonResponse
    {
        $note = $request->user()->notes()->findOrFail($id);
        $note->update($request->only(['title', 'body']));

        return response()->json($note);
    }

    public function destroy(Request $request, $id): JsonResponse
    {
        $request->user()->notes()->findOrFail($id)->delete();

        return response()->json(null, 204);
    }
}
