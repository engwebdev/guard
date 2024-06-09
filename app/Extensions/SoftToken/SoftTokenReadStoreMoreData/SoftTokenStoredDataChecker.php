<?php

namespace App\Extensions\SoftToken\SoftTokenReadStoreMoreData;

use App\Extensions\SoftToken\SoftTokenIdentified;

class SoftTokenStoredDataChecker
{
    public string|null $matchDataStatus = null;
    protected array $config;
    protected SoftTokenIdentified $softTokenIdentify;
    public array|null $matchData = [];

    /**
     * @throws \Exception
     */
    public function __construct(array $config, SoftTokenIdentified $softTokenIdentify)
    {
        $this->config = $config;
        $this->softTokenIdentify = $softTokenIdentify;
        $this->getDataFromStore();
    }

    protected function getDataFromStore(): void
    {
        foreach ($this->config as $key => $value) {
            if (empty($value)) {
                $message = 'Undefined model and identify key';
                $this->setCheckUnMatch('- not found -', '- not found -', $key, $message);
//                throw new \Exception($message);
            }
            elseif (count($value) < 2) {
                $message = 'Undefined identify key';
                $this->setCheckUnMatch('- not found -', '- not found -', $key, $message);
//                throw new \Exception($message);
            }
            else {
//                dd($this->softTokenIdentify->AccessTokenClaims);
                $modelEntity = "App\Models\\" . ucfirst(strtolower($value[0]));
                $modelIdName = $value[1];
                $modelIdValueFromTokenClaimKey = $this->softTokenIdentify->AccessTokenClaims[$key];
                $model = $modelEntity::where($modelIdName, '=', $modelIdValueFromTokenClaimKey)
                    ->first();
                if(!$model){
                    $model = [];
                    $message = 'The claim key '.$key.' not match with '.$value[0].' '.$value[1];
                    $this->setCheckUnMatch($value[0], $value[1], $key, $message);
                }else{
                    $model = $model->toArray();
                    $message = null;
                    $this->setCheckMatch($value[0], $value[1], $key);
                }
            }
        }
    }



    private function setCheckUnMatch($modelName, $modelId, $tokenClaimKey, $message): void
    {
        $this->matchData[$tokenClaimKey] = [$modelName. ': ' .$modelId, false, $message];
        $this->matchDataStatus = $message;
    }

    private function setCheckMatch($modelName, $modelId, $tokenClaimKey): void
    {
        $this->matchData[$tokenClaimKey] = [$modelName .': '. $modelId, true];
    }

    public function getMatchData(): ?array
    {
        return $this->matchData;
    }

}
