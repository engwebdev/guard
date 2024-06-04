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
//        dd($this);
    }

    public function loadTokenData(): SoftTokenIdentified
    {
        $this->checkConfig();
        $AccessToken = $this->softToken->AccessToken;
        $id = $this->softToken->AccessTokenID;
//        $id = 1;

        $tokenEntity = SoftGuard::$tokenModel::select('id', 'name', 'tokenable_type', 'tokenable_id')
            ->where('id', '=', $id)
            ->first();
        if (!$tokenEntity) {
            $this->softToken->AccessTokenEntityData = [];
        }
        else {
            $this->softToken->AccessTokenEntityData = $tokenEntity->toArray();
        }
        // loads data
        return $this->softToken;
    }

    private function checkConfig()
    {
        if ($this->statefulDriverConfig) {
            $query = $this->statefulDriverConfigToQuery();
            dd($query);
        }
    }

    private function statefulDriverConfigToQuery()
    {
        $tokenEntity = SoftGuard::$tokenModel::query();
        $tokenEntity->select($this->statefulDriverConfig['select']);
        foreach ($this->statefulDriverConfig['where'] as $item){
            $tokenEntity->orwhere(function ($tokenEntity) use ($item) {
                foreach ($item as $key => $value) {
                    $tokenEntity->where($key, $value);
                }
            });
        }
        $result = $tokenEntity->first()->toArray();
//        $result = $tokenEntity->toArray();
        return $result;
    }
}
