<?php
return [
    /*
    |--------------------------------------------------------------------------
    | JWT Authentication Secret
    |--------------------------------------------------------------------------
    |
    | Don't forget to set this in your .env file, as it will be used to sign
    | your tokens. A helper command is provided for this:
    | `php artisan jwt:secret`
    |
    | Note: This will be used for Symmetric algorithms only (HMAC),
    | since RSA and ECDSA use a private/public key combo (See below).
    |
    */

    'validator' => [
        'headers' => [
            'authorization' => [
                'prefix' => 'bearer',
                'secretSigner' => '',
                'algo' => '',
                'ttl' => env('JWT_TTL', 60)
            ],
            'test' => [
                'prefix' => null,
                'secretSigner' => env('JWT_SECRET'),
                'algo' => '',
                'ttl' => env('JWT_TTL', 60)
            ]
        ],
        'RouteParams' => [
            'token' => [
                'secretSigner' => '',
                'algo' => '',
                'ttl' => env('JWT_TTL', 60)
            ],
            'test' => [
                'secretSigner' => '',
                'algo' => '',
                'ttl' => env('JWT_TTL', 60)
            ]
        ],
        'QueryStrings' => [
            'token' => [
                'secretSigner' => '',
                'algo' => '',
                'ttl' => env('JWT_TTL', 60)
            ],
            'test' => [
                'secretSigner' => '',
                'algo' => '',
                'ttl' => env('JWT_TTL', 60)
            ]
        ],
        'Cookies' => [
            'authorization' => [
                'decrypt' => false,
                'secretSigner' => '',
                'algo' => '',
                'ttl' => env('JWT_TTL', 60)
            ],
            'token' => [
                'decrypt' => true,
                'secretSigner' => '',
                'algo' => '',
                'ttl' => env('JWT_TTL', 60)
            ]
        ]
    ],

    /*
    |--------------------------------------------------------------------------
    | JWT time to live
    |--------------------------------------------------------------------------
    |
    | Specify the length of time (in minutes) that the token will be valid for.
    | Defaults to 1 hour.
    |
    | You can also set this to null, to yield a never expiring token.
    | Some people may want this behaviour for e.g. a mobile app.
    | This is not particularly recommended, so make sure you have appropriate
    | systems in place to revoke the token if necessary.
    | Notice: If you set this to null you should remove 'exp' element from 'required_claims' list.
    |
    */

    'test' => env('test', 60),
    'secretSigner' => env('JWT_SECRET'),
    'algo' => env('algo', 'HS256'),
    'ttl' => env('JWT_TTL', 60),
    'state' => env('state', 'database'),
    'headerMetaData' => env('headerMetaData', []),
    'databaseClaims' => env('databaseClaims', []),


];
