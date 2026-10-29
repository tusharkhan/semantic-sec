<?php

namespace App\Http\Controllers\Vuln;

use App\Http\Controllers\Controller;
use App\Http\Requests\Vuln\UpdateAccountRequest;
use Illuminate\Http\JsonResponse;

class AccountController extends Controller
{
    public function update(UpdateAccountRequest $request): JsonResponse
    {
        $account = $request->user()->account;
        $account->update($request->all());

        return response()->json($account);
    }
}
