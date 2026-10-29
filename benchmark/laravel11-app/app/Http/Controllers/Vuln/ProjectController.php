<?php

namespace App\Http\Controllers\Vuln;

use App\Http\Controllers\Controller;
use App\Http\Requests\Vuln\UpdateProjectRequest;
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
