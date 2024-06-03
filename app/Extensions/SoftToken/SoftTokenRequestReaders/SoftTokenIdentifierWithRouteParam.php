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

            $secretKeys = [
                'secretSigner' => $secretSigner,
            ];
//            $secretKeys = [
//                'publicKey' => $publicKey,
//                'privetKey' => $privetKey,
//            ];

            $methodology = new SoftGuard::$methodologies[$algo](
                $this->AccessToken,
                $secretKeys, // todo standard
            );
            $methodology->decode();
            $Identified->identifyStatus = $methodology->tokenStatus;
            $Identified->setProviderModelIdentify($this->config['provider'], $methodology->claims['sub']);
            $Identified->AccessTokenID = $methodology->claims['jti'];
            $Identified->AccessToken = $this->AccessToken;
            $Identified->AccessTokenClaims = $methodology->claims;
            if ($this->config['state'] == 'database') {
                $tokenEntity = SoftGuard::$tokenModel::where('id', '=', $Identified->AccessTokenID)->first()->toArray();
//                \App\Models\Token::where('id', '=', $Identified->AccessTokenID)->first();
//                $Identified->AccessTokenEntityData = []; // todo
                $Identified->AccessTokenEntityData = $tokenEntity; // todo
            }
            else {
                $Identified->AccessTokenEntityData = [];
            }
            $this->Identify = $Identified;
        }
        catch (\Exception $ex) {
            dd($ex);
            $Identified->identifyStatus = $ex->getMessage();
            $this->Identify = $Identified;
        }
    }

    protected function GetTokenFromRequestRouteParam($keyWord, $prefix)
    {
        $routeParam = $this->request->input($keyWord);
        $position = strrpos($routeParam, $prefix . ' ');
        if ($position !== false) {
            $header = substr($routeParam, $position + 7);
            $value = str_contains($routeParam, ',') ? strstr($routeParam, ',', true) : $routeParam;
            return $value;
        }
        return $routeParam;
    }

}
