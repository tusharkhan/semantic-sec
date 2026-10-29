<?php

namespace App\Http\Controllers\Safe;

use App\Http\Controllers\Controller;
use App\Models\Note;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class NoteController extends Controller
{
    public function __construct()
    {
        $this->authorizeResource(Note::class, 'note');
    }

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

    public function show(Note $note): JsonResponse
    {
        return response()->json($note);
    }

    public function update(Request $request, Note $note): JsonResponse
    {
        $note->update($request->only(['title', 'body']));

        return response()->json($note);
    }

    public function destroy(Note $note): JsonResponse
    {
        $note->delete();

        return response()->json(null, 204);
    }
}
