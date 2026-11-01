<?php

namespace App\Http\Controllers\Vuln;

use App\Http\Controllers\Controller;
use App\Models\Subscription;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

class SubscriptionController extends Controller
{
    public function pause(Request $request, Subscription $subscription): JsonResponse
    {
        Gate::authorize('pause-subscription', $subscription);

        $weeks = $request->validate(['weeks' => ['required', 'integer', 'between:1,8']])['weeks'];

        $subscription->status = 'paused';
        $subscription->paused_until = now()->addWeeks($weeks);
        $subscription->save();

        return response()->json($subscription);
    }
}
