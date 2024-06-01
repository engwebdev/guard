<?php

namespace App\Extensions;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

//use Firebase\JWT\SignatureInvalidException;
use Illuminate\Support\Facades\Config;
use PhpParser\Node\Expr\Cast\String_;
use stdClass;

class SoftToken
{
    protected string $tokenStatus;
    private array $tokenConfig = [
        'alg' => 'HS256', //
    ];
    private array $baseClaims = [
        "iss" => "", // Issued from url
        "iat" => "", // Issued At date
        "exp" => "", // Expiration Time
        "nbf" => "", // Not Before
    ];

    private array $reservedClaims = [
        "sub" => "", // Subject ID
        "aud" => "", // Audience
        "jti" => "", // JWT ID
    ];

    private array $customClaims = [

    ];

    private array $privateClaims = [

    ];

    public array $publicClaims = [

    ];

    private array $optionalClaims = [

    ];
    private string $secretSigner;
    private string $tokenString;

    public function __construct()
    {
//        $this->secretSigner = $secretSigner;
//        $this->baseClaims['iss'] = '';
    }

    public function initialSoftToken($body, $headers, $secretSigner, $config = null): void
    {
        $defaultTTL = Config::get('soft.ttl');
        if ( ( empty($secretSigner) ) ) {
            $this->secretSigner = Config::get('soft.secretSigner');
        }
        else {
            $this->secretSigner = $secretSigner;
        }
        $this->tokenBodyExtract($body);
        if ((!isset($this->baseClaims['iss']))) {
            $this->baseClaims['iss'] = 'url';
        }
        if ((!isset($this->baseClaims['iat'])) or (empty($this->baseClaims['iat']))) {
            $this->baseClaims['iat'] = Carbon::now()->getTimestamp();
        }
        if ((!isset($this->baseClaims['exp'])) or (empty($this->baseClaims['exp']))) {
            $this->baseClaims['exp'] = Carbon::now()->addMinutes((int)$defaultTTL)->getTimestamp();
//            dd($this->baseClaims['exp']); // 1716998347
        }
        if ((!isset($this->baseClaims['nbf'])) or (empty($this->baseClaims['nbf']))) {
            $this->baseClaims['nbf'] = Carbon::now()->getTimestamp();
        }
        if ((!isset($this->baseClaims['iss'])) or (empty($this->baseClaims['iss']))) {
            $this->baseClaims['iss'] = 'url';
        }
        $this->tokenHeaderExtract($headers);
        if ((!isset($this->tokenConfig['alg'])) or (empty($this->tokenConfig['alg']))) {
            $this->tokenConfig['alg'] = $config['alg'];
        }
        if ((!isset($this->tokenConfig['typ'])) or (empty($this->tokenConfig['typ']))) {
            if (!isset($config['typ'])) {
                $this->tokenConfig['typ'] = 'JWT';
            }
            else {
                $this->tokenConfig['typ'] = $config['typ'];
            }
        }
        foreach ($body as $key => $value){
            $this->publicClaims[$key] = $value;
        }
// $this->initialSoftToken($decoded_array, $headers, $secretSigner);

//        "sub" => "", // Subject ID
//        "aud" => "", // Audience
//        "jti" => "", // JWT ID
    }

    public function makeTokenString(string $secretSigner, array $data, array $tokenConfig = null): string
    {
        $this->secretSigner = $secretSigner;
        $decoded_array = $data['claims'];

        if (!isset($data['headers'])) {
            $headers = null;
        }
        else {
            $headers = $data['headers'];
        }
        if (!isset($data['alg'])) {
            $data['alg'] = $this->tokenConfig['alg'];
        }
        if (!isset($data['keyId'])) {
            $data['keyId'] = null;
        }
        $this->initialSoftToken($decoded_array, $headers, $secretSigner);

        try {
            $this->tokenString = JWT::encode(
                $decoded_array,
                $this->secretSigner,
                $data['alg'],
                $data['keyId'],
                $headers,
            );
        }
        catch (\Exception $ex) {
//            dd($ex, 1);
//            $value = $ex->getPayload();
            $this->tokenStatus = $ex->getMessage();
        }
//        return type is stdClass
//        $decoded = JWT::decode($payload, $keys);
//        cast to array
//        $decoded = json_decode(json_encode($decoded), true);

//        $this->tokenBodyExtract($decoded_array);

//        return $this;
        return $this->tokenString;
    }

    public function TokenStringConvertToObject(string $secretSigner, string $string): static
    {
        $this->tokenString = $string;
        $this->secretSigner = $secretSigner;
        try {
            $value = JWT::decode($this->tokenString, new Key($this->secretSigner, $this->tokenConfig['alg']));
        }
        catch (\Exception $ex) {
//            dd($this->tokenStatus = $ex->getMessage());
            $value = $ex->getPayload();
            $this->tokenStatus = $ex->getMessage();
        }
        $decoded_value = (array)$value;


        list($headersB64, $payloadB64, $sig) = explode('.', $this->tokenString);
        $header = json_decode(base64_decode($headersB64), true);
        $decoded_header = (array)$header;

        $this->initialSoftToken($decoded_value, $decoded_header, $secretSigner);

        return $this;
    }

    private function tokenBodyExtract($decoded_value): void
    {
        if (isset($decoded_value['iss'])) {
            $this->baseClaims['iss'] = $decoded_value['iss'];
            unset($decoded_value['iss']);
        }
        if (isset($decoded_value['iat'])) {
            $this->baseClaims['iat'] = $decoded_value['iat'];
            unset($decoded_value['iat']);
        }
        if (isset($decoded_value['exp'])) {
            $this->baseClaims['exp'] = $decoded_value['exp'];
            unset($decoded_value['exp']);
        }
        if (isset($decoded_value['nbf'])) {
            $this->baseClaims['nbf'] = $decoded_value['nbf'];
            unset($decoded_value['nbf']);
        }
        if (isset($decoded_value['sub'])) {
            $this->reservedClaims['sub'] = $decoded_value['sub'];
            unset($decoded_value['sub']);
        }
        if (isset($decoded_value['aud'])) {
            $this->reservedClaims['aud'] = $decoded_value['aud'];
            unset($decoded_value['aud']);
        }
        if (isset($decoded_value['jti'])) {
            $this->reservedClaims['jti'] = $decoded_value['jti'];
            unset($decoded_value['jti']);
        }
        if (is_array($decoded_value)) {
            foreach ($decoded_value as $key => $val) {
                $this->optionalClaims[$key] = $val;
                unset($decoded_value[$key]);
            }
        }

    }

    private function tokenHeaderExtract($decoded_header): void
    {
        if (isset($decoded_header['typ'])) {
            $this->tokenConfig['typ'] = $decoded_header['typ'];
            unset($decoded_header['typ']);
        }
        if (isset($decoded_header['alg'])) {
            $this->tokenConfig['alg'] = $decoded_header['alg'];
            unset($decoded_header['alg']);
        }
        if (is_array($decoded_header)) {
            foreach ($decoded_header as $key => $val) {
                $this->tokenConfig[$key] = $val;
                unset($decoded_header[$key]);
            }
        }

    }

    /**
     * @param $jwt
     * @param $key
     * @return stdClass|null
     */
    public function GetTokenPayloads($jwt, $key): ?stdClass
    {
        try {
            $stdClass = $headers = new stdClass();
            $decoded = JWT::decode($jwt, new Key($key, 'HS256'));
//            dd($decoded);
            return $decoded;
        }
//        catch (\Firebase\JWT\SignatureInvalidException $ex) {
        catch (\Exception $ex) {
            return null;
            // todo handle exception
            // return null
            // InvalidArgumentException
            // UnexpectedValueException
            // SignatureInvalidException
            // BeforeValidException
            // ExpiredException
        }

    }

    public function setTokenPayloads($payload, $key)
    {
        $headers = [
//            'one' => 'two'
        ];
//        dd($decoded_array = (array) $payload);
        $decoded_array = (array)$payload;
        $jwt = JWT::encode($decoded_array, $key, 'HS256', null, $headers);
        dd($jwt);
        return $jwt;
    }

    public function getSubjectIdentifier()
    {
//        dd($this->reservedClaims['sub']);
        if(!isset($this->reservedClaims['sub'])){
//            foreach (allClaims){
//
//            }
            return null;
            // exception
        }
        return $this->reservedClaims['sub'];
    }

    public function setSubjectIdentifier($identifier): void
    {
        $this->reservedClaims['sub'] = $identifier;
    }

    public function getTokenStatus(): string
    {
        return $this->tokenStatus;
    }

    protected function validateStructure($token)
    {
        return $token;
    }

    public function setTokenExpiration($minute)
    {
        $this->baseClaims['exp'] = Carbon::now()->addMinutes($minute)->getTimestamp();
//        dd(Carbon::now(), Carbon::now()->getTimestamp() ,$this->baseClaims['exp']);
    }

    public function getTokenExpiration()
    {
        $this->tokenString = '';

    }

}
