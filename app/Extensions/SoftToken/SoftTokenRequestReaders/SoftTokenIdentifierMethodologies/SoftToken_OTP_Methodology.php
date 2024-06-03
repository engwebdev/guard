<?php

namespace App\Extensions\SoftToken\SoftTokenRequestReaders\SoftTokenIdentifierMethodologies;

class SoftToken_OTP_Methodology
{
    protected mixed $tokenString;
    protected mixed $otpDecoder;
    public string $tokenStatus;
    public array $claims;

    public function __construct($accessToken, $otpDecoder)
    {
        $this->tokenString = $accessToken;
        $this->otpDecoder = $otpDecoder;
    }

    public function decode()
    {
        $claims = [];
        //
        $this->claims = $claims;
    }

}
