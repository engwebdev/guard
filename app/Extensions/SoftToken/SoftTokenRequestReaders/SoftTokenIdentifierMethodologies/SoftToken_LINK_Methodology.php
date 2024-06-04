<?php

namespace App\Extensions\SoftToken\SoftTokenRequestReaders\SoftTokenIdentifierMethodologies;

class SoftToken_LINK_Methodology
{
    protected mixed $tokenString;
    protected mixed $linkDecoder;
    public string|null $tokenStatus = null;
    public array $claims;

    public function __construct($accessToken, $linkDecoder)
    {
        $this->tokenString = $accessToken;
        $this->linkDecoder = $linkDecoder;
    }

    public function decode()
    {
        $claims = [];
        //
        $this->claims = $claims;
    }


}
