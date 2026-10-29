<?php

namespace App\Http\Controllers\Safe;

use App\Http\Controllers\Controller;
use App\Services\DownloadRepository;
use Symfony\Component\HttpFoundation\BinaryFileResponse;

class DownloadController extends Controller
{
    public function __construct(private readonly DownloadRepository $downloads)
    {
    }

    public function show(int $id): BinaryFileResponse
    {
        $download = $this->downloads->find($id);

        return response()->download(storage_path("app/downloads/{$download->path}"), $download->name);
    }
}
