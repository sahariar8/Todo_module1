<?php

namespace App\Http\Controllers;

use App\Helper\JWTToken;
use App\Http\Controllers\Controller;
use App\Mail\OTPMail;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;

class AuthController extends Controller
{
    public function registration(Request $request)
    {
        $request->validate([
            'name' => 'required|min:3',
            'email' => 'required|email',
            'password' => 'required|min:8',
        ]);
        User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password)
        ]);

        return response()->json([
            'status' => 'success',
            'message' => 'User created successfully'
        ], 200);
    }

    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|min:8',
        ]);

        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json([
                'status' => 'error',
                'message' => 'Invalid credentials'
            ], 401);
        }

        $token = JWTToken::createToken($user->email, $user->id);

        return response()->json([
            'status' => 'success',
            'message' => 'User logged in successfully',
            'access_token' => $token,
            'token_type' => 'Bearer',
        ])->cookie('token', $token, time() + 60 * 24 * 30);
    }

    public function sendOTP(Request $request)
    {
        $request->validate([
            'email' => 'required|email',

        ]);

        $user = User::where('email', $request->email)->first();

        if (!$user) {
            return response()->json([
                'status' => 'error',
                'message' => 'Invalid OTP'
            ], 401);
        }
        #create otp
        $otp = rand(100000, 999999);

        #send otp
        Mail::to($request->email)->send(new OTPMail($otp));

        #update otp into user
        $user->update(['otp' => $otp]);

        return response()->json([
            'status' => 'success',
            'message' => 'OTP sent successfully',
            'otp' => $otp
        ]);
    }

    public function verifyOTP(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'otp' => 'required',
        ]);

        $user = User::where('email', $request->email)->first();

        if (!$user || $user->otp != $request->otp) {
            return response()->json([
                'status' => 'error',
                'message' => 'Invalid OTP'
            ], 401);
        }

        if ($user->updated_at->diffInMinutes() > 5) {
            return response()->json([
                'status' => 'error',
                'message' => 'OTP expired'
            ], 401);
        }

        #update otp into user
        $user->update(['otp' => 0]);

        #generate token for set new password
        $token = JWTToken::CreateTokenForResetPassword($user->email, $user->id);
        return response()->json([
            'status' => 'success',
            'message' => 'OTP verified successfully',
            'token' => $token,
        ]);
    }

    public function resetPassword(Request $request)
    {
        $request->validate([
            'password' => 'required|min:8',
        ]);

        $email = $request->header('email');

        user::where('email', $email)->update(['password' => bcrypt($request->password)]);

        return response()->json([
            'status' => 'success',
            'message' => 'Password Updated successfully',
        ]);
    }

    public function logout(Request $request)
    {
        return response()->json([
            'status' => 'success',
            'message' => 'Logged out successfully'
        ], 200)->cookie('token', '', -1);
    }
}
