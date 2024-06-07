<?php

namespace App\Extensions\SoftToken\SoftTokenStatefulDrivers;

use App\Extensions\SoftToken\SoftGuard;
use App\Extensions\SoftToken\SoftTokenIdentified;

class SoftTokenStatefulDriversDefault
{
    private SoftTokenIdentified $softToken;
    protected ?array $statefulDriverConfig;

    public function __construct($token, array $statefulDriverConfig = null)
    {
        $this->softToken = $token;
        $this->statefulDriverConfig = $statefulDriverConfig;
//        dd($this->softToken);
    }

    public function loadTokenData()
    {
        $this->checkConfig();
        $AccessToken = $this->softToken->AccessToken;
        $id = $this->softToken->AccessTokenID;
//        $id = 1;

        $tokenEntity = SoftGuard::$tokenModel::query();
        if ($this->statefulDriverConfig) {
            $tokenEntity = $this->statefulDriverConfigToQuery($tokenEntity);
            if (!$tokenEntity) {
                $tokenEntity = [];
//                $this->softToken->AccessTokenEntityData = [];
            }
            else {
                $tokenEntity = $tokenEntity->toArray();
//                $this->softToken->AccessTokenEntityData = $tokenEntity->toArray();
            }
        }
        else {
        $tokenEntity = SoftGuard::$tokenModel::select('id', 'name', 'tokenable_type', 'tokenable_id', 'token', 'expires_at')
            ->where('token', '=', $AccessToken)
            ->first();
            $tokenEntity = $tokenEntity->toArray();
//            $this->softToken->AccessTokenEntityData = $tokenEntity;
        }
        // loads data
        return $tokenEntity;
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
