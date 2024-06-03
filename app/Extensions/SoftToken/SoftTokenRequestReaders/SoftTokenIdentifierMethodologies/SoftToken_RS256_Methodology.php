<?php

namespace App\Extensions\SoftToken\SoftTokenRequestReaders\SoftTokenIdentifierMethodologies;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class SoftToken_RS256_Methodology
{
    protected mixed $tokenString;
    protected array $secretSigner;
    protected string $publicKey;
    protected string $privetKey;
    public string $tokenStatus;
    public array $claims;

    public function __construct($accessToken, $secretSigner)
    {
        $this->tokenString = $accessToken;
        $this->secretSigner = $secretSigner;
        $this->publicKey = $secretSigner['publicKey'];
        $this->privetKey = $secretSigner['privetKey'];
    }

    public function decode()
    {
        try {
            $value = JWT::decode($this->tokenString, new Key($this->secretSigner['publicKey'], 'RS256'));
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
