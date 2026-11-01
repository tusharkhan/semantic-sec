<?php

namespace App\Http\Middleware;

use App\Models\Store;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EnsureStoreOwner
{
    public function handle(Request $request, Closure $next): Response
    {
        $store = $request->route('store');

        abort_unless($store instanceof Store && $store->user_id === $request->user()->id, 403);

        return $next($request);
    }
}
