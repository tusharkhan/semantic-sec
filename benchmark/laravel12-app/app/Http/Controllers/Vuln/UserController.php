<?php

namespace App\Http\Controllers\Vuln;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;

class UserController extends Controller
{
    public function suspend(User $user): JsonResponse
    {
        $user->forceFill(['suspended_at' => now()])->save();

        return response()->json($user->only(['id', 'name', 'suspended_at']));
    }
}
