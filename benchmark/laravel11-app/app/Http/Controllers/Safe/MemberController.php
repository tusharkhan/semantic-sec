<?php

namespace App\Http\Controllers\Safe;

use App\Http\Controllers\Controller;
use App\Http\Requests\Safe\UpdateMemberRequest;
use Illuminate\Http\JsonResponse;

class MemberController extends Controller
{
    public function update(UpdateMemberRequest $request): JsonResponse
    {
        $member = $request->user()->member;
        $member->update($request->validated());

        return response()->json($member);
    }
}
