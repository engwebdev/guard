<?php

namespace App\Http\Controllers\Api\Jwt;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class JwtController extends Controller
{
//    public $user;
//    public function __construct($user)
//    {
//        $this->middleware('auth:jwt', ['except' => ['login']]);
//        $this->user = $user;
//    }

    public function register(Request $request): JsonResponse
    {
        // validate the incoming request
        // set every field as required
        // set email field so it only accept the valid email format

//        $this->validate($request, [
//            'name' => 'required|string|min:2|max:255',
//            'email' => 'required|string|email:rfc,dns|max:255|unique:users',
//            'password' => 'required|string|min:6|max:255',
//        ]);

        // if the request valid, create user

        $user = User::create([
            'name' => $request['name'],
            'email' => $request['email'],
            'password' => bcrypt($request['password']),
        ]);

        // login the user immediately and generate the token
        $token = $this->login($user);

        // return the response as json
        return response()->json([
            'meta' => [
                'code' => 200,
                'status' => 'success',
                'message' => 'User created successfully!',
            ],
            'data' => [
                'user' => $user,
                'access_token' => [
                    'token' => $token,
                    'type' => 'Bearer',
                    'expires_in' => auth('jwt')->factory()->getTTL() * 600,    // get token expires in seconds
                ],
            ],
        ]);
    }


    /**
     * Get a JWT via given credentials.
     *
     * @return JsonResponse
     */
    public function login(Request $request): JsonResponse
    {
//        $this->validate($request, [
//            'email' => 'required|string',
//            'password' => 'required|string',
//        ]);

        // attempt a login (validate the credentials provided)
        $token = auth('jwt')->attempt([
            'email' => $request->email,
            'password' => $request->password,
        ]);

        dd(auth('jwt'));
        // eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDAvYXBpL2p3dC9sb2dpbiIsImlhdCI6MTcxNTQ0NzA1MiwiZXhwIjoxNzE1NDUwNjUyLCJuYmYiOjE3MTU0NDcwNTIsImp0aSI6IjRjVkNLeTdVY3FVdm5udWsiLCJzdWIiOiIxIiwicHJ2IjoiMjNiZDVjODk0OWY2MDBhZGIzOWU3MDFjNDAwODcyZGI3YTU5NzZmNyJ9.L9mhTriGgKMFCdmmr8Ti9KNb91FHk84qwovXr9cjNfg
        // if token successfully generated then display success response
        // if attempt failed then "unauthenticated" will be returned automatically
        if ($token)
        {
            return response()->json([
                'meta' => [
                    'code' => 200,
                    'status' => 'success',
                    'message' => 'Quote fetched successfully.',
                ],
                'data' => [
                    'user' => auth('jwt')->user(),
                    'access_token' => [
                        'token' => $token,
                        'type' => 'Bearer',
                        'expires_in' => auth('jwt')->factory()->getTTL() * 60,
                    ],
                ],
            ]);
        }else{
            return response()->json([]);
        }
    }

    /**
     * Get the authenticated User.
     *
     * @return JsonResponse
     */
    public function me(): JsonResponse
    {
        return response()->json(auth('jwt')->user());

        // dd($this->parseToken('bearer', 'jwt')->authenticate());
        // JWTAuth::parseToken('bearer', 'jwt')->authenticate();
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return JsonResponse
     */
    public function logout(): JsonResponse
    {
        auth('jwt')->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return JsonResponse
     */
    public function refresh(): JsonResponse
    {
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return JsonResponse
     */
    protected function respondWithToken($token): JsonResponse
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth('jwt')->factory()->getTTL() * 60
        ]);
    }
}
