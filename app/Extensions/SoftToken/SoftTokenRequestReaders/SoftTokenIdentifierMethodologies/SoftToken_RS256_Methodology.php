<?php

namespace App\Extensions\SoftToken\SoftTokenRequestReaders\SoftTokenIdentifierMethodologies;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class SoftToken_RS256_Methodology
{
    protected mixed $tokenString;
    protected array $methodologyConfig;
    protected string $publicKey;
    protected string $privetKey;
    public string|null $tokenStatus = null;
    public array $claims;

    public function __construct($accessToken, $methodologyConfig)
    {
        $this->tokenString = $accessToken;
        $this->methodologyConfig = $methodologyConfig;
        $this->publicKey = $methodologyConfig['publicKey'];
        $this->privetKey = $methodologyConfig['privetKey'];
    }

    public function decode()
    {
        try {
            $value = JWT::decode($this->tokenString, new Key($this->publicKey, 'RS256'));
            $this->claims = (array) $value;
        }
        catch (\Exception $ex) {
            if(method_exists($ex, 'getPayload')){
                $value = $ex->getPayload();
            }else{
                $value = [];
            }
            $this->claims = (array) $value;
            $this->tokenStatus = $ex->getMessage();
        }
    }


}
