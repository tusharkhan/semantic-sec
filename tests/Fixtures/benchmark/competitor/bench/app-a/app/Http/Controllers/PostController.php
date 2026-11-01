<?php

namespace App\Http\Controllers;

class PostController extends Controller
{
    public function show(string $post)
    {
        return $post;
    }
}
