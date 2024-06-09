<?php

namespace App\Extensions\SoftToken\SoftTokenStatefulDrivers;

use App\Extensions\SoftToken\SoftGuard;
use App\Extensions\SoftToken\SoftTokenIdentified;
use Carbon\Carbon;

class SoftTokenStatefulDriversDefault
{
    private ?string $accessToken;
    protected ?array $statefulDriverConfig;
    protected ?string $status;
    protected ?string $AccessTokenID;
    protected ?string $AccessTokenName;
    protected ?int $AccessTokenExpirationTime;
    protected ?array $AccessTokenEntityData;

    public function __construct($accessToken, array $statefulDriverConfig = null)
    {
        $this->accessToken = $accessToken;
        $this->statefulDriverConfig = $statefulDriverConfig;
//        dd($this->softToken);
    }

    public function loadTokenData()
    {
//        $this->checkConfig();
        $AccessToken = $this->accessToken;
        $tokenEntity = SoftGuard::$tokenModel::query();
//        if ($this->statefulDriverConfig) {
//            $tokenEntity = $this->statefulDriverConfigToQuery($tokenEntity);
//            dd($tokenEntity);
//            if (!$tokenEntity) {
//                $tokenEntity = [];
//                $this->status = '';
//                $this->AccessTokenID = null;
//                $this->AccessTokenName = null;
//                $this->AccessTokenExpirationTime = Carbon::now()->subMinutes(30)->getTimestampMs();
//            }
//            else {
//                $tokenEntity = $tokenEntity->toArray();
//                $this->status = null;
//                $this->AccessTokenID = $tokenEntity->id;
//                $this->AccessTokenName = $tokenEntity->name;
//                $this->AccessTokenExpirationTime = $tokenEntity->expires_at;
//            }
//        }
//        else {
//            $tokenEntity = SoftGuard::$tokenModel::select('id', 'name', 'expires_at')
            $tokenEntity = SoftGuard::$tokenModel::select('*')
                ->where('token', '=', $AccessToken)
                ->first();
            if (!$tokenEntity) {
                $tokenEntity = [];
                $this->status = '';
                $this->AccessTokenID = null;
                $this->AccessTokenName = null;
                $this->AccessTokenExpirationTime = Carbon::now()->subMinutes(30)->getTimestampMs();
                $this->AccessTokenEntityData = $tokenEntity;
            }
            else {
                $tokenEntity = $tokenEntity->toArray();
                $this->status = null;
                $this->AccessTokenID = $tokenEntity['id'];
                $this->AccessTokenName = $tokenEntity['name'];
                $this->AccessTokenExpirationTime = $tokenEntity['expires_at'];
                $this->AccessTokenEntityData = $tokenEntity;
            }
//        }
        // loads data
//        return [
//            'status' => $status,
//            'AccessTokenID' => $AccessTokenID,
//            'AccessTokenName' => $AccessTokenName,
//            'AccessTokenExpirationTime' => $AccessTokenExpirationTime,
//        ];
    }

    public function getStatus(): ?string
    {
        return $this->status;
    }

    public function getAccessTokenID(): ?string
    {
        return $this->AccessTokenID;
    }

    public function getAccessTokenName(): ?string
    {
        return $this->AccessTokenName;
    }

    public function getAccessTokenExpirationTime(): ?int
    {
        return $this->AccessTokenExpirationTime;
    }

    public function getAccessTokenEntityData(): ?array
    {
        return $this->AccessTokenEntityData;
    }
    public function getProviderModelName(): ?string
    {
        return $this->AccessTokenEntityData['tokenable_type'];
    }
    public function getProviderModelId(): ?string
    {
        return $this->AccessTokenEntityData['tokenable_id'];
    }
    private function checkConfig(): void
    {
        try {
            if ($this->statefulDriverConfig) {
                if ($this->statefulDriverConfig['where']) {
                    foreach ($this->statefulDriverConfig['where'] as $itemKey => $item) {
                        foreach ($item as $column => $value) {
                            if ($value == 'AccessTokenID') {
                                $value = (string)$this->softToken->AccessTokenID;
                                $this->statefulDriverConfig['where'][$itemKey][$column] = $value;
                            }
                            if ($value == 'AccessToken') {
                                $value = (string)$this->softToken->AccessToken;
                                $this->statefulDriverConfig['where'][$itemKey][$column] = $value;
                            }
                            if ($value == 'providerModelName') {
                                $value = (string)$this->softToken->getProviderModelName();
                                $this->statefulDriverConfig['where'][$itemKey][$column] = $value;
                            }
                            if ($value == 'providerModelID') {
                                $value = (string)$this->softToken->getProviderModelID();
                                $this->statefulDriverConfig['where'][$itemKey][$column] = $value;
                            }
                        }
                    }
                }
            }
        }
        catch (\Exception $ex) {
            $tokenStatus = "Invalid Stateful Driver Config... => " . $ex->getMessage();
            $exception = new \Exception($tokenStatus);
//            $exception->setPayload($claims);
            throw $exception;
        }

    }

    private function statefulDriverConfigToQuery($tokenEntity)
    {
        try {
//            $tokenEntity = SoftGuard::$tokenModel::query();
            if (isset($this->statefulDriverConfig['select'])) {
                $tokenEntity->select($this->statefulDriverConfig['select']);
            }
            if ($this->statefulDriverConfig['where']) {
                foreach ($this->statefulDriverConfig['where'] as $item) {
                    $tokenEntity->orwhere(function ($tokenEntity) use ($item) {
                        foreach ($item as $key => $value) {
                            $tokenEntity->where($key, $value);
                        }
                    });
                }
            }
            $result = $tokenEntity->first();
        }
        catch (\Exception $ex) {
            $tokenStatus = "Invalid Stateful Driver Config... => " . $ex->getMessage();
            $exception = new \Exception($tokenStatus);
//            $exception->setPayload($claims);
            throw $exception;
        }
        return $result;
    }
}
