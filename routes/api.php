<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

use App\Models\Http\Controllers\Api\Sanctum\SanctumController;
use App\Models\Http\Controllers\Api\Jwt\JwtController;

// //////////////////////////////////////////////////////

Route::get('test/test', function (Request $request) {
//    return 11;
    $encodedToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDAvYXBpL2p3dC9sb2dpbiIsImlhdCI6MTcxNTg2MTg5MCwiZXhwIjoxNzE1ODY1NDkwLCJuYmYiOjE3MTU4NjE4OTAsImp0aSI6ImE0YnJLVDM5TEhPTDJ3YWgiLCJzdWIiOiIxIiwicHJ2IjoiMjNiZDVjODk0OWY2MDBhZGIzOWU3MDFjNDAwODcyZGI3YTU5NzZmNyJ9.X94LRYRyTjYzB-gIniHYKt_xcxFSO8h1_BS8JfpmxqE";
    $private_key = "";
    $public_key = "";


    list($header, $payload, $signature) = explode('.', $encodedToken);
//    dd($header, $payload, $signature);
    $jsonTokenHeader = base64_decode($header);
    $arrayTokenHeader = json_decode($jsonTokenHeader, true);

    $jsonTokenPayload = base64_decode($payload);
    $arrayTokenPayload = json_decode($jsonTokenPayload, true);

    $jsonTokenSignature = base64_decode($signature);
    $arrayTokenSignature = json_decode($jsonTokenSignature, true);
// ---------------------------- //

// ------------------------- //
    dd($header, $arrayTokenHeader, $payload, $arrayTokenPayload, $signature, $jsonTokenSignature);
});

// //////////////////////////////////////////////////////

//$middleware = [
//    "authenticate_session" => "Laravel\Sanctum\Http\Middleware\AuthenticateSession",
//    "encrypt_cookies" => "Illuminate\Cookie\Middleware\EncryptCookies",
//    "validate_csrf_token" => "Illuminate\Foundation\Http\Middleware\ValidateCsrfToken",
//];

Route::post('/sanctum/register', [SanctumController::class, 'registerUser'])
    ->name('sanctum.register');
Route::post('/sanctum/login', [SanctumController::class, 'loginUser'])
    ->name('sanctum.register');


Route::middleware(['auth:sanctum'])
    ->prefix('sanctum')
    ->group(function () {

        Route::get('/test', function (Request $request) {
//            return 'sanctum test';
            dd(Auth('sanctum'));
        });

    });


// //////////////////////////////////////////////////////
// D5ewwKZXGrBrWEjLFJ4cnNf79q8xbEh3raVJyGFGkcjPP0oa5UJBqEqrcjzJFDnm
Route::post('/jwt/register', [JwtController::class, 'register'])
    ->name('jwt.register');
Route::post('/jwt/login', [JwtController::class, 'login'])
    ->name('jwt.login');


Route::middleware(['auth:jwt'])
    ->prefix('jwt')
    ->group(function () {

        Route::get('/test', function (Request $request) {
//            return 'jwt test';
            dd(Auth('jwt'));
        });

//        Route::post('/logout', [[JwtController::class, '']]);
//        Route::post('refresh', [JwtController::class, '']);
//        Route::post('me', [JwtController::class, '']);
    });

// //////////////////////////////////////////////////////

Route::middleware(['auth:passport'])
    ->prefix('passport')
    ->group(function () {

        Route::get('/test', function (Request $request) {
//            return 'passport test';
            dd(Auth('passport'));
        });

    });

//  personal [Laravel Personal Access Client]
//  Client ID ............................................................. 3
//  Client secret .................. IxXYwWmbVdCikHjRkPkK5lwF4VQcjSrReNoQx3bU

// //////////////////////////////////////////////////////

Route::middleware(['auth:soft'])
    ->prefix('soft')
    ->group(function () {

        Route::get('/test', function (Request $request) {
//            return 'soft test';
            dd(Auth('soft'),'get');
        });

        Route::post('/test', function (Request $request) {
//            return 'soft test';
            dd(Auth('soft'),'post');
        });

        Route::put('/test', function (Request $request) {
//            return 'soft test';
            dd(Auth('soft'),'put');
        });

        Route::patch('/test', function (Request $request) {
//            return 'soft test';
            dd(Auth('soft'),'patch');
        });

        Route::delete('/test', function (Request $request) {
//            return 'soft test';
            dd(Auth('soft'),'delete');
        });

        Route::options('/test', function (Request $request) {
//            return 'soft test';
            dd(Auth('soft'),'options');
        });

        Route::match('HEAD', '/test', function (Request $request) {
//            return 'soft test';
            dd(Auth('soft'),'options');
        });


//        Route::redirect('/test', function (Request $request) {
////            return 'soft test';
//            dd(Auth('soft'));
//        });

    });
