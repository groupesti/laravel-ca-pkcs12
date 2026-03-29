<?php

declare(strict_types=1);

use CA\Pkcs12\Http\Controllers\Pkcs12Controller;
use Illuminate\Support\Facades\Route;

Route::post('/', [Pkcs12Controller::class, 'create'])->name('ca.pkcs12.create');
Route::get('/{uuid}', [Pkcs12Controller::class, 'show'])->name('ca.pkcs12.show');
Route::post('/{uuid}/export', [Pkcs12Controller::class, 'export'])->name('ca.pkcs12.export');
Route::post('/import', [Pkcs12Controller::class, 'import'])->name('ca.pkcs12.import');
