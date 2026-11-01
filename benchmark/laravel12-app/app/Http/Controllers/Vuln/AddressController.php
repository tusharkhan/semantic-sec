<?php

namespace App\Http\Controllers\Vuln;

use App\Http\Controllers\Controller;
use App\Models\Address;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class AddressController extends Controller
{
    public function update(Request $request, int $id): JsonResponse
    {
        $data = $request->validate([
            'line1' => ['required', 'string', 'max:255'],
            'city' => ['required', 'string', 'max:120'],
            'postcode' => ['required', 'string', 'max:16'],
        ]);

        $address = Address::findOrFail($id);
        $address->update($data);

        return response()->json($address);
    }
}
