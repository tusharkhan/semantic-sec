<?php

namespace App\Http\Controllers\Safe;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Gate;

class UserController extends Controller
{
    public function suspend(User $user): JsonResponse
    {
        Gate::authorize('suspend', $user);

        $user->forceFill(['suspended_at' => now()])->save();

        return response()->json($user->only(['id', 'name', 'suspended_at']));
    }
}
