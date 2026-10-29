<?php

namespace App\Services;

use App\Models\Download;

class OwnedDownloadService
{
    public function find(int $id): Download
    {
        return Download::where('owner_id', auth()->id())->findOrFail($id);
    }
}
