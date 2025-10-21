<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\WalletAuthController;

Route::post('/wc/nonce', [WalletAuthController::class, 'nonce']);
Route::post('/wc/verify', [WalletAuthController::class, 'verify']);
