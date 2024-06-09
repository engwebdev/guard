<?php

namespace App\Extensions\SoftToken\SoftTokenRequestReaders;

use App\Extensions\SoftToken\SoftGuard;
use App\Extensions\SoftToken\SoftTokenIdentified;
use App\Models\Token;
use Illuminate\Http\Request;


class SoftTokenIdentifierWithHeader
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


    private function initialRequestReader(): void
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
                $this->AccessToken = $this->GetTokenFromRequestHeader($keyword, $prefix);

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
            $Identified->setIdentifyStatusLogs($Identified->identifyStatus, 'IdentifierWith Methodology ' . (string)$algo );
            $Identified->setProviderModelIdentify($this->config['provider'], $this->Methodology->claims['sub']);
            $Identified->AccessTokenID = $this->Methodology->claims['jti'];
            $Identified->AccessToken = $this->AccessToken;
            $Identified->AccessTokenClaims = $this->Methodology->claims;

//        dd($methodology, $Identified);

            $this->Identify = $Identified;
        }
        catch (\Exception $ex) {
            $Identified->identifyStatus = $ex->getMessage();
            $Identified->setIdentifyStatusLogs($Identified->identifyStatus, 'IdentifierWithHeader');
            $this->Identify = $Identified;
        }
    }

    protected function GetTokenFromRequestHeader($keyWord, $prefix)
    {
        $header = $this->request->header($keyWord, '');
        $position = strrpos($header, $prefix . ' ');
        if ($position !== false) {
            $header = substr($header, $position + 7);
            $value = str_contains($header, ',') ? strstr($header, ',', true) : $header;
            return $value;
        }
        return $header;
    }


    public function loader(): void
    {
        $type = key($this->config['validator']);
//        $methodologyConfig = $this->config['validator'][$type];
        $keyword = $this->config['validator'][$type]['keyword'];
        $prefix = $this->config['validator'][$type]['prefix'];

        if ((is_array($keyword)) and (is_array($prefix))) {
            if(count($keyword) != count($prefix)){
                $this->status = 'keyword and prefix is not match.';
                $this->AccessToken = null;
                $this->AccessTokens = [];
            }else{
                foreach ($keyword as $key => $value){
                    $AccessToken = $this->GetTokenFromRequestHeader($value, $prefix[$key]);
                    $this->status = null;
                    $this->AccessToken = $AccessToken;
                    $this->AccessTokens[(string) $value] = [$this->AccessToken];
                }
            }
        }
        else {
            $AccessToken = $this->GetTokenFromRequestHeader($keyword, $prefix);
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
