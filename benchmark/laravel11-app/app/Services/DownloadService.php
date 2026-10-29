<?php

namespace App\Services;

use App\Models\Download;

class DownloadService
{
    public function find(int $id): Download
    {
        return Download::findOrFail($id);
    }
}
