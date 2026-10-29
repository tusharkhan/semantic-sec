<?php

use Illuminate\Support\Facades\Route;

Route::middleware('auth')->group(function () {
    Route::prefix('vuln')->group(function () {
        Route::get('/reports/{report}', 'Vuln\ReportController@show');
    });

    Route::prefix('safe')->group(function () {
        Route::get('/reports/{report}', 'Safe\ReportController@show');
    });

    Route::resource('vuln/notes', 'Vuln\NoteController');
    Route::resource('safe/notes', 'Safe\NoteController');
});
