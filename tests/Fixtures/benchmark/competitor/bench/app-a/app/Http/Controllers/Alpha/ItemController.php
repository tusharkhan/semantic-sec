<?php

namespace App\Http\Controllers\Alpha;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;

class ItemController extends Controller
{
    public function show(Request $request, int $id)
    {
        return $request->user()->items()->findOrFail($id);
    }
}
