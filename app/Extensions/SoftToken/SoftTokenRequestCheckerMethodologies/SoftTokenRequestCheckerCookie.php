<?php

namespace App\Extensions\SoftToken\SoftTokenRequestCheckerMethodologies;

use App\Extensions\SoftToken\SoftTokenIdentified;
use Illuminate\Http\Request;

class SoftTokenRequestCheckerCookie
{
    public string|null $matchDataStatus = null;
    protected array|null $checkAbleData = [];
    protected SoftTokenIdentified $softToken;
    protected Request $request;
    public array|null $matchData = [];

    public function __construct(array $data, Request $request, SoftTokenIdentified $softTokenIdentify)
    {
        $this->checkAbleData = $data;
        $this->softToken = $softTokenIdentify;
        $this->request = $request;
        $this->getMetaDataFromRequestCookie();
    }

    protected function getMetaDataFromRequestCookie(): void
    {
        foreach ($this->checkAbleData as $key => $value) {
            $matchAble = $this->request->cookie($key);
            if (!isset($this->softToken->AccessTokenClaims[$value])) {
                $message = 'In Cookie checker undefined array key ' . $value . ' in claims';
                $this->setCheckUnMatch($key, $value, $message);
            }
            else {
                if ($matchAble == $this->softToken->AccessTokenClaims[$value]) {
                    $this->setCheckMatch($key, $value);
                }
                else {
                    $message = 'The Cookie ' . $key . ' value is not equal to the claim ' . $value . ' value';
                    $this->setCheckUnMatch($key, $value, $message);
                }
            }
        }
//        dd($this->matchData);
    }

    private function setCheckUnMatch($headerKeyName, $tokenClaimName, $message): void
    {
        $this->matchData[$headerKeyName] = [$tokenClaimName, false, $message];
        $this->matchDataStatus = $message;
    }

    private function setCheckMatch($headerKeyName, $tokenClaimName): void
    {
        $this->matchData[$headerKeyName] = [$tokenClaimName, true];
    }

    /**
     * @return array|null
     */
    public function getCheckAbleData(): ?array
    {
        return $this->checkAbleData;
    }

    public function getMatchData(): ?array
    {
        return $this->matchData;
    }


}
