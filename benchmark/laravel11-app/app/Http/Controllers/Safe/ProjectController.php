<?php

namespace App\Http\Controllers\Safe;

use App\Http\Controllers\Controller;
use App\Http\Requests\Safe\UpdateProjectRequest;
use App\Models\Project;
use Illuminate\Http\JsonResponse;

class ProjectController extends Controller
{
    public function update(UpdateProjectRequest $request, Project $project): JsonResponse
    {
        $project->update($request->validated());

        return response()->json($project);
    }
}
