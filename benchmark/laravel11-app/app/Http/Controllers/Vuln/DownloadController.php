<?php

namespace App\Http\Controllers\Vuln;

use App\Http\Controllers\Controller;
use App\Services\DownloadService;
use Symfony\Component\HttpFoundation\BinaryFileResponse;

class DownloadController extends Controller
{
    public function __construct(private readonly DownloadService $downloads)
    {
    }

    public function show(int $id): BinaryFileResponse
    {
        $download = $this->downloads->find($id);

        return response()->download(storage_path("app/downloads/{$download->path}"), $download->name);
    }
}
