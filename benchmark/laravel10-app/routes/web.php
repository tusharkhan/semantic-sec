<?php

use Illuminate\Support\Facades\Route;

Route::middleware('auth')->group(function () {
    Route::prefix('vuln')->group(function () {
        Route::get('/reports/{report}', 'Vuln\ReportController@show');
    });

    Route::prefix('safe')->group(function () {
        Route::get('/reports/{report}', 'Safe\ReportController@show');
    });

    Route::resource('vuln/notes', 'Vuln\NoteController')->names('vuln.notes')->except(['create', 'edit']);
    Route::resource('safe/notes', 'Safe\NoteController')->names('safe.notes')->except(['create', 'edit']);
});
