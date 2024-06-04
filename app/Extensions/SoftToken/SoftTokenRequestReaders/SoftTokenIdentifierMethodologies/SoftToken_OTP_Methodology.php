<?php

namespace App\Extensions\SoftToken\SoftTokenRequestReaders\SoftTokenIdentifierMethodologies;

use App\Extensions\SoftToken\SoftGuard;
use Carbon\Carbon;

class SoftToken_OTP_Methodology
{
    protected string $tokenString;
    protected array $methodologyConfig;
    public string|null $tokenStatus = null;
    public array $claims;

    public function __construct($accessToken, $methodologyConfig)
    {
        $this->tokenString = $accessToken;
        $this->methodologyConfig = $methodologyConfig;
//        dd($this->methodologyConfig);
    }

    public function decode()
    {
        $model = SoftGuard::$tokenModel;
        $record = $model::select()
            ->where('token', '=', $this->tokenString)
            ->first();
        if (!$record) {
            $claims = [];
            // todo make new Exception
            $this->tokenStatus = "Invalid otp code";
            $exception = new \Exception($this->tokenStatus);
//            $exception->setPayload($claims);
            throw $exception;
        }
        else {
            // todo check otp time
            // Expired otp
            $claims = $record->toArray();
            $ttl = (int)$this->methodologyConfig['ttl'];
            if ($claims['expires_at'] < Carbon::now()->addMinutes($ttl)->getTimestampMs()) {
                $this->tokenStatus = "Expired otp code";
                $exception = new \Exception($this->tokenStatus);
//            $exception->setPayload($claims);
                throw $exception;
            }
            else {
                $claims['jti'] = $claims['id'];
                $claims['sub'] = $claims['tokenable_id'];
                $this->claims = $claims;
            }
        }
    }

}
