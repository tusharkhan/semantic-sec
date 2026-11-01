<?php

namespace App\Http\Controllers\Vuln;

use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class ProfileController extends Controller
{
    public function update(Request $request): JsonResponse
    {
        $request->validate([
            'name' => ['sometimes', 'string', 'max:255'],
            'email' => ['sometimes', 'email', 'max:255'],
        ]);

        $request->user()->forceFill($request->except('password'))->save();

        return response()->json($request->user());
    }
}
