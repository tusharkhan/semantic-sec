<?php

namespace App\Http\Controllers\Vuln;

use App\Http\Controllers\Controller;
use App\Http\Requests\Vuln\StoreTeamRequest;
use App\Models\Team;
use Illuminate\Http\JsonResponse;

class TeamController extends Controller
{
    public function store(StoreTeamRequest $request): JsonResponse
    {
        $team = Team::create($request->all());

        return response()->json($team, 201);
    }
}
