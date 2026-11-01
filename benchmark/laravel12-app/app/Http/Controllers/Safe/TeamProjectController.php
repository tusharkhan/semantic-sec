<?php

namespace App\Http\Controllers\Safe;

use App\Http\Controllers\Controller;
use App\Models\Project;
use App\Models\Team;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Gate;

class TeamProjectController extends Controller
{
    public function show(Team $team, Project $project): JsonResponse
    {
        Gate::authorize('view', $team);

        return response()->json($project);
    }
}
