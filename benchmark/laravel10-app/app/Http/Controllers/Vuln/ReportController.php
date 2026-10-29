<?php

namespace App\Http\Controllers\Vuln;

use App\Http\Controllers\Controller;
use App\Models\Report;
use Illuminate\Http\JsonResponse;

class ReportController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth');
    }

    public function show(Report $report): JsonResponse
    {
        return response()->json($report);
    }
}
