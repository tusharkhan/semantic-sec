<?php

namespace App\Http\Controllers\Vuln;

use App\Http\Controllers\Controller;
use App\Http\Requests\Vuln\UpdateListingRequest;
use App\Models\Listing;
use Illuminate\Http\JsonResponse;

class ListingController extends Controller
{
    public function update(UpdateListingRequest $request, Listing $listing): JsonResponse
    {
        $listing->update($request->validated());

        return response()->json($listing);
    }
}
