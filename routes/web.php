<?php

use Illuminate\Support\Facades\Route;


Route::view('/wallet-connect', 'walletconnect');

Route::get('/', function () {
    return view('welcome');
});
