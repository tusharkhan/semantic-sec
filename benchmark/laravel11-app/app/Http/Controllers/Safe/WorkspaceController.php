<?php

namespace App\Http\Controllers\Safe;

use App\Http\Controllers\Controller;
use App\Http\Requests\Safe\StoreWorkspaceRequest;
use Illuminate\Http\JsonResponse;

class WorkspaceController extends Controller
{
    public function store(StoreWorkspaceRequest $request): JsonResponse
    {
        $workspace = $request->user()->ownedWorkspaces()->create($request->validated());

        return response()->json($workspace, 201);
    }
}
