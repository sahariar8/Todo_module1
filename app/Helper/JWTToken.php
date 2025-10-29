<?php

namespace App\Helper;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class JWTToken
{
    /**
     * Create a new class instance.
     */
    public function __construct()
    {
        //
    }

    public static function CreateToken($userEmail, $userID)
    {
        $key = env('JWT_KEY');
        $payload = [
            'iss' => 'Laravel Todo',
            'iat' => time(),
            'exp' => time() + 60 * 60,
            'userEmail' => $userEmail,
            'userID' => $userID
        ];

        return JWT::encode($payload, $key, 'HS256');
    }

    public static function CreateTokenForResetPassword($userEmail, $userID)
    {
        $key = env('JWT_KEY');
        $payload = [
            'iss' => 'Laravel Todo',
            'iat' => time(),
            'exp' => time() + 5 * 60,
            'userEmail' => $userEmail,
            'userID' => $userID
        ];

        return  JWT::encode($payload, $key, 'HS256');
    }

    public static function VerifyToken($token)
    {
        $key = env('JWT_KEY');

        if (empty($token)) {
            return "unauthorized";
        }

        try {
            $decode = JWT::decode($token, new Key($key, 'HS256'));
            return $decode->userEmail; // Return just the email if success
        } catch (\Exception $e) {
            return "unauthorized";
        }
    }
}
