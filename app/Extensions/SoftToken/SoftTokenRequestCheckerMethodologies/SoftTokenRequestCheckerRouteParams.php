<?php

namespace App\Extensions\SoftToken\SoftTokenRequestCheckerMethodologies;

use App\Extensions\SoftToken\SoftTokenIdentified;
use Illuminate\Http\Request;

class SoftTokenRequestCheckerRouteParams
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
        $this->getMetaDataFromRequestRouteParam();
    }

    protected function getMetaDataFromRequestRouteParam(): void
    {
        foreach ($this->checkAbleData as $key => $value) {
            $matchAble = $this->request->request->get($key);
            if (!isset($this->softToken->AccessTokenClaims[$value])) {
                $message = 'In route param checker undefined array key ' . $value . ' in claims';
                $this->setCheckUnMatch($key, $value, $message);
            }
            else {
                if ($matchAble == $this->softToken->AccessTokenClaims[$value]) {
                    $this->setCheckMatch($key, $value);
                }
                else {
                    $message = 'The route param ' . $key . ' value is not equal to the claim ' . $value . ' value';
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

    public function getMatchDataStatus(): ?string
    {
        return $this->matchDataStatus;
    }
    public function getCheckAbleData(): ?array
    {
        return $this->checkAbleData;
    }
    public function getMatchData(): ?array
    {
        return $this->matchData;
    }

}
