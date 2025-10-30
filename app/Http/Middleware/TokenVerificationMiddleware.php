<?php

namespace App\Http\Middleware;

use App\Helper\JWTToken;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class TokenVerificationMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        #you can use Token in Header 
        // $token = $request->header('token');

        #you can use Token in Authorization Header

        $authorizationHeader = $request->header('Authorization');
        $token = str_replace('Bearer ', '', $authorizationHeader);

        $result = JWTToken::VerifyToken($token);

        if ($result === "unauthorized") {
            return response()->json([
                'status' => 'failed',
                'message' => 'Unauthorized'
            ], 401);
        }

        // Attach decoded email to request headers
        $request->attributes->set('email', $result['email']);
        $request->attributes->set('user_id', $result['id']);

        return $next($request);
    }
}
