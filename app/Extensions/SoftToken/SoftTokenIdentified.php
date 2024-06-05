<?php

namespace App\Extensions\SoftToken;

class SoftTokenIdentified
{
    public string|null $identifyStatus = null;
    /**
     * provider Model Name
     *
     * @var string|null
     */
    private string|null $providerModelName = null;

    /**
     * ID Provider Model
     *
     * @var string|null
     */
    private string|null $providerModelID = null;

    /**
     * Provider Model Identify
     *
     * @var array|null[]
     */
    public array $providerModelIdentify = [
        'providerModelName' => null,
        'providerModelID' => null,
    ];

    /**
     * ID Access Token
     *
     * @var string|null
     */
    public string|null $AccessTokenID = null;

//    /**
//     * Name Access Token
//     *
//     * @var string|null
//     */
//    public string|null $AccessTokenName = null;

    /**
     * Access Token
     *
     * @var string|null
     */
    public string|null $AccessToken = null;

    /**
     * Access Token Claims
     *
     * @var array|null
     */
    public array|null $AccessTokenClaims = [];

    /**
     * Access Token Entity Data
     *
     * @var array|null
     */
    public array|null $AccessTokenEntityData = [];

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
        $this->AccessTokenID= null; // jti
        $this->AccessToken = null; // token string
        $this->AccessTokenClaims = []; // token claims
        $this->AccessTokenEntityData = []; // token data from table
        return $this;
    }
}
