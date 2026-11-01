<?php

namespace App\Http\Controllers\Beta;

use App\Http\Controllers\Controller;
use App\Models\Item;

class ItemController extends Controller
{
    public function show(int $id)
    {
        // looked up by raw id
        return Item::findOrFail($id);
    }
}
