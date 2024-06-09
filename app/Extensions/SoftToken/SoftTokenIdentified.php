<?php

namespace App\Extensions\SoftToken;

class SoftTokenIdentified
{
    public string|null $identifyStatus = null;
    public array|null $identifyStatusLogs = [];
    public string|null $AccessToken = null;
    public array|null $AccessTokenClaims = [];
    public string|null $AccessTokenID = null;
    public string|null $AccessTokenName = null;
    public string|null $AccessTokenExpirationTime = null;
    public array|null $AccessTokenEntityData = [];
    public array|null $RequestMetaData = [];
    private string|null $providerModelName = null;
    private string|null $providerModelID = null;
    public array $providerModelIdentify = [
        'providerModelName' => null,
        'providerModelID' => null,
    ];
    public array|null $providerModelEntityData = [];
    public array|null $MoreModelEntityData = [];

    public function setProviderModelName(?string $providerModelName): void
    {
        $this->providerModelName = $providerModelName;
        $this->providerModelIdentify['providerModelName'] = ($this->providerModelName);
    }

    public function getProviderModelName(): ?string
    {
        return $this->providerModelName;
    }

    public function setProviderModelID(?string $providerModelID): void
    {
        $this->providerModelID = $providerModelID;
        $this->providerModelIdentify['providerModelID'] = ($this->providerModelID);
    }

    public function getProviderModelID(): ?string
    {
        return $this->providerModelID;
    }

    public function getProviderModelIdentify(): array
    {
        return $this->providerModelIdentify;
    }

    public function setProviderModelIdentify($providerModelName, $providerModelID): void
    {
        $this->providerModelName = $providerModelName;
        $this->providerModelID = $providerModelID;
        $this->providerModelIdentify = [
            'providerModelName' => ($this->providerModelName),
            'providerModelID' => ($this->providerModelID),
        ];
    }

//    public function getIdentifiedWithAccessToken(string $AccessToken, $methodology): static
    public function getIdentified(): static
    {
//        $this->IdentifierMethodology($methodology, $AccessToken); // todo not need
//        $this->AccessToken = $AccessToken;
        // todo decode AccessToken
        // set claims
        return $this;
    }

    public function setIdentified(): static
    {
//        $this->IdentifierMethodology($methodology, $AccessToken); // todo not need
        // todo set Identified
        $this->providerModelIdentify = []; // [model => user, modelId => user_id]
        $this->AccessTokenID = null; // jti
        $this->AccessToken = null; // token string
        $this->AccessTokenClaims = []; // token claims
        $this->AccessTokenEntityData = []; // token data from table
        return $this;
    }

    public function getIdentifyStatusLogs(): ?array
    {
        return $this->identifyStatusLogs;
    }

    public function setIdentifyStatusLogs($message, $Key = null): void
    {
        if($message != null){
            $this->identifyStatus = $message;
        }
        if (!empty($Key)) {
            $this->identifyStatusLogs[] = [$Key => $message];
        }
        else {
            $this->identifyStatusLogs[] = [$message];
        }
    }

    public function setAccessToken(?string $AccessToken): void
    {
        $this->AccessToken = $AccessToken;
    }

    public function getAccessToken(): ?string
    {
        return $this->AccessToken;
    }

    public function getAccessTokenClaims(): ?array
    {
        return $this->AccessTokenClaims;
    }

    public function setAccessTokenClaims(?array $AccessTokenClaims): void
    {
        $this->AccessTokenClaims = $AccessTokenClaims;
    }

    public function setAccessTokenID(?string $AccessTokenID): void
    {
        $this->AccessTokenID = $AccessTokenID;
    }

    public function setAccessTokenName(?string $AccessTokenName): void
    {
        $this->AccessTokenName = $AccessTokenName;
    }

    public function setAccessTokenExpirationTime(?string $AccessTokenExpirationTime): void
    {
        $this->AccessTokenExpirationTime = $AccessTokenExpirationTime;
    }

    public function setAccessTokenEntityData(?array $AccessTokenEntityData): void
    {
        $this->AccessTokenEntityData = $AccessTokenEntityData;
    }

    public function getRequestMetaData(): ?array
    {
        return $this->RequestMetaData;
    }

    public function setRequestMetaData(array|string|null $RequestMetaData): void
    {
        if(is_array($RequestMetaData)){
            $this->RequestMetaData[key($RequestMetaData)] = $RequestMetaData[key($RequestMetaData)];
        }else{
            $this->RequestMetaData[] = $RequestMetaData;
        }
    }

    public function getProviderModelEntityData(): ?array
    {
        return $this->providerModelEntityData;
    }

    public function setProviderModelEntityData(?array $providerModelEntityData): void
    {
        $this->providerModelEntityData = $providerModelEntityData;
    }
}
