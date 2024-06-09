<?php

namespace App\Extensions\SoftToken\SoftTokenRequestReaders;

use App\Extensions\SoftToken\SoftGuard;
use App\Extensions\SoftToken\SoftTokenIdentified;
use Illuminate\Http\Request;

class SoftTokenIdentifierWithRouteParam
{
    protected mixed $Methodology; // instance of Methodology todo
    protected string $AccessToken;
    public SoftTokenIdentified $Identify;
    protected Request $request;
    protected mixed $config;
    public string|null $status;
    public array|null $AccessTokens;
    public array $claims;

    public function __construct(Request $request, $config)
    {
        $this->request = $request;
        $this->config = $config;
        $this->initialRequestReader();
//        $this->Identify = new SoftTokenIdentified();
    }

    public function getIdentified(): SoftTokenIdentified
    {
        return $this->Identify;
    }


    function initialRequestReader(): void
    {
        $Identified = new SoftTokenIdentified();
        try {
            $type = key($this->config['validator']);
            $methodologyConfig = $this->config['validator'][$type];

            $keyword = $this->config['validator'][$type]['keyword'];
            $prefix = $this->config['validator'][$type]['prefix'];

            $secretSigner = $this->config['validator'][$type]['secretSigner'];
            $algo = $this->config['validator'][$type]['algo'];
            $ttl = $this->config['validator'][$type]['ttl'];

            if ((is_array($keyword)) and (is_array($prefix))) {
//            foreach (){
//            }
            }
            else {
                $this->AccessToken = $this->GetTokenFromRequestRouteParam($keyword, $prefix);
            }

//            $secretKeys = [
//                'secretSigner' => $secretSigner,
//            ];
//            $secretKeys = [
//                'publicKey' => $publicKey,
//                'privetKey' => $privetKey,
//            ];

            $this->Methodology = new SoftGuard::$methodologies[$algo](
                $this->AccessToken,
                $methodologyConfig,
            );
            $this->Methodology->decode();
            $Identified->identifyStatus = $this->Methodology->tokenStatus;
            $Identified->setIdentifyStatusLogs($Identified->identifyStatus, 'IdentifierWith Methodology ' . (string)$algo);
            $Identified->setProviderModelIdentify($this->config['provider'], $this->Methodology->claims['sub']);// todo
            $Identified->AccessTokenID = $this->Methodology->claims['jti'];// todo
            $Identified->AccessToken = $this->AccessToken;
            $Identified->AccessTokenClaims = $this->Methodology->claims;// todo
            $this->Identify = $Identified;
        }
        catch (\Exception $ex) {
//            dd($ex);
            $Identified->identifyStatus = $ex->getMessage();
            $Identified->setIdentifyStatusLogs($Identified->identifyStatus, 'IdentifierWithRouteParam');
            $this->Identify = $Identified;
        }
    }

    protected function GetTokenFromRequestRouteParam($keyWord, $prefix)
    {
        $routeParam = $this->request->input($keyWord);
        $position = strrpos($routeParam, $prefix . ' ');
        if ($position !== false) {
            $routeParam = substr($routeParam, $position + 7);
            $value = str_contains($routeParam, ',') ? strstr($routeParam, ',', true) : $routeParam;
            return $value;
        }
        return $routeParam;
    }

    public function loader(): void
    {
        $type = key($this->config['validator']);
//        $methodologyConfig = $this->config['validator'][$type];
        $keyword = $this->config['validator'][$type]['keyword'];
        $prefix = $this->config['validator'][$type]['prefix'];

        if ((is_array($keyword)) and (is_array($prefix))) {
            if (count($keyword) != count($prefix)) {
                $this->status = 'keyword and prefix is not match.';
                $this->AccessToken = null;
                $this->AccessTokens = [];
            }
            else {
                foreach ($keyword as $key => $value) {
                    $AccessToken = $this->GetTokenFromRequestRouteParam($value, $prefix[$key]);
                    $this->status = null;
                    $this->AccessToken = $AccessToken;
                    $this->AccessTokens[(string)$value] = [$this->AccessToken];
                }
            }
        }
        else {
            $AccessToken = $this->GetTokenFromRequestRouteParam($keyword, $prefix);
            $this->status = null;
            $this->AccessToken = $AccessToken;
        }
    }

    public function getAccessToken(): ?string
    {
        return $this->AccessToken;
    }

    public function getStatus(): ?string
    {
        return $this->status;
    }

}
