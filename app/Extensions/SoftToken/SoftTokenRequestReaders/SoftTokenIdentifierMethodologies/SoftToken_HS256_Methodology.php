<?php

namespace App\Extensions\SoftToken\SoftTokenRequestReaders\SoftTokenIdentifierMethodologies;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class SoftToken_HS256_Methodology
{
    protected mixed $tokenString;
    protected mixed $secretSigner;
    public string $tokenStatus;
    public array $claims;

    public function __construct($accessToken, $secretSigner)
    {
        $this->tokenString = $accessToken;
        $this->secretSigner = $secretSigner;
    }

    public function decode()
    {
        try {
            $value = JWT::decode(
                $this->tokenString,
                new Key($this->secretSigner['secretSigner'],'HS256')
            );
            $this->claims = (array)$value;
        }
        catch (\Exception $ex) {
            if (method_exists($ex, 'getPayload')) {
                $value = $ex->getPayload();
            }
            else {
                $value = [];
            }
            $this->claims = (array)$value;
            $this->tokenStatus = $ex->getMessage();
        }
    }
}
