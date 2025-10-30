<?php

use App\Http\Controllers\AuthController;
use App\Http\Middleware\TokenVerificationMiddleware;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;


//registration & login using JWTToken

Route::post('user-registration',[AuthController::class,'registration']);
Route::post('user-login',[AuthController::class,'login'])->name('login');

//OTP send
Route::post('send-otp',[AuthController::class,'sendOTP']);
//otp verify
Route::post('verify-otp',[AuthController::class,'verifyOTP']);

#password reset
Route::post('password-reset',[AuthController::class,'resetPassword'])->middleware(TokenVerificationMiddleware::class);
#logout
Route::get('logout',[AuthController::class,'logout'])->middleware(TokenVerificationMiddleware::class);