<?php

namespace App\Extensions\SoftToken;

//use App\Extensions\SoftToken\SoftTokenRequestReaders\SoftTokenIdentifierWithHeader;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;

//use Illuminate\Support\Str;

class SoftGuard implements Guard
{
    public static array $requestReaders = [
        'Headers' => "\App\Extensions\SoftToken\SoftTokenRequestReaders\SoftTokenIdentifierWithHeader",
        'RouteParams' => "\App\Extensions\SoftToken\SoftTokenRequestReaders\SoftTokenIdentifierWithRouteParam",
        'QueryStrings' => "\App\Extensions\SoftToken\SoftTokenRequestReaders\SoftTokenIdentifierWithQueryString",
        'Cookies' => "\App\Extensions\SoftToken\SoftTokenRequestReaders\SoftTokenIdentifierWithCookie",
    ];
    public static array $methodologies = [ // file.php load
        'HS256' => "\App\Extensions\SoftToken\SoftTokenRequestReaders\SoftTokenIdentifierMethodologies\SoftToken_HS256_Methodology", // read from Header
        'RS256' => "\App\Extensions\SoftToken\SoftTokenRequestReaders\SoftTokenIdentifierMethodologies\SoftToken_RS256_Methodology", // read from Header
        'OTP' => "\App\Extensions\SoftToken\SoftTokenRequestReaders\SoftTokenIdentifierMethodologies\SoftToken_OTP_Methodology", // read from RouteParams
        'LINK' => "\App\Extensions\SoftToken\SoftTokenRequestReaders\SoftTokenIdentifierMethodologies\SoftToken_LINK_Methodology", // read from QueryStrings
    ];

    public static string $tokenModel = "\App\Models\Token";

    protected UserProvider $provider;
    public ?Authenticatable $user;
    protected Request $request;
    protected array $config;
    protected mixed $RequestReader;
    private mixed $methodology;
    protected array $defaultConfig;

    public function __construct(
        UserProvider $provider,
        Request      $request,
                     $configuration
    )
    {
        $this->provider = $provider;
        $this->request = $request;
        $this->defaultConfig = Config::get('soft');
        $this->config = $this->initialSoftConfig($configuration, $this->defaultConfig);
//        dd($configuration, $this->config);
//        $this->initialSoftConfig();
//        $token = $this->request->bearerToken();
    }

    //////////////////////////////////////////////
    public function RequestReader($config): SoftTokenIdentified
    {
//        dd(key($config['validator']));
//        $this->RequestReader = $requestReader;
//        $this->methodology = $methodology;
//        $this->request = $request;
        $result = new SoftTokenIdentified();
        if(!in_array(key($config['validator']), array_keys(self::$requestReaders))){
            $result->identifyStatus = 'Request Validator Not Match request Readers.';
            return $result;
        }
        foreach (self::$requestReaders as $key => $value) {
//            $reader = \Illuminate\Support\Str::of($key)->lower();
//            $requestReadAble = \Illuminate\Support\Str::of(key($config['validator']))->lower();
            if ($key === key($config['validator'])) {
                $requestReader = new self::$requestReaders[key($config['validator'])](
                    $this->request,
                    $this->config
                );
                $result = $requestReader->getIdentified();
                break;
            }
        }
        return $result;
    }


    //////////////////////////////////////////////

    public function user(): ?Authenticatable
    {
//        dd($this);
//        $this->provider
//        $softTokenIdentify = $this->RequestReader($this->RequestReader, $this->methodology);
        $softTokenIdentify = $this->RequestReader($this->config);
        $tokenIdentify = $softTokenIdentify->getIdentified();

        dd($tokenIdentify);
        if($tokenIdentify->identifyStatus != null){
            return null;
        }
        $this->user = $this->provider->retrieveById($tokenIdentify['providerModelID']);
        // TODO: Implement user() method.
        return $this->user;
    }

    public function check(): bool
    {
        return !is_null($this->user());
        // TODO: Implement check() method.
    }

    public function guest()
    {
        // TODO: Implement guest() method.
    }

    public function id()
    {
        // TODO: Implement id() method.
    }

    public function validate(array $credentials = [])
    {
        // TODO: Implement validate() method.
    }

    public function hasUser()
    {
        // TODO: Implement hasUser() method.
    }

    public function setUser(Authenticatable $user)
    {
        // TODO: Implement setUser() method.
    }

    /////////////////////////////////////

    public function initialSoftConfig($config, $defaultConfig): array
    {
        if (!isset($config['driver'])) {
            $initialedSoftConfig['driver'] = 'soft';
        }
        else {
            $initialedSoftConfig['driver'] = $config['driver'];
        }

        if (!isset($config['provider'])) {
            $initialedSoftConfig['provider'] = 'users';
        }
        else {
            $initialedSoftConfig['provider'] = $config['provider'];
        }

        if (!isset($config['validator'])) {
            $initialedSoftConfig = array_merge($config, [
                'validator' => [],
            ]);
        }

        if (!key($config['validator'])) {
            $type = 'headers';
        }
        else {
            $type = key($config['validator']);
        }

        if (!isset($config['validator'][$type]['keyword'])) { // todo check array
            $initialedSoftConfig['validator'][$type]['keyword'] = 'Authorization';
        }
        else {
            $initialedSoftConfig['validator'][$type]['keyword'] = $config['validator'][$type]['keyword'];
        }

        if (!isset($config['validator'][$type]['prefix'])) { // todo check array
            $initialedSoftConfig['validator'][$type]['prefix'] = 'Bearer';
        }
        else {
            $initialedSoftConfig['validator'][$type]['prefix'] = $config['validator'][$type]['prefix'];
        }

        if (!isset($config['validator'][$type]['algo'])) {
            if (!isset($defaultConfig['algo'])) {
                $algo = 'HS256';
            }
            else {
                $algo = $defaultConfig['algo'];
            }
        }
        else {
            $algo = $config['validator'][$type]['algo'];
        }
        $initialedSoftConfig['validator'][$type]['algo'] = $algo;

        if ($algo == 'HS256') {
            if (!isset($config['validator'][$type]['secretSigner'])) {
                if (!isset($defaultConfig['secretSigner'])) {
                    $secretSigner = null;
                }
                else {
                    $secretSigner = $defaultConfig['secretSigner'];
                }
            }
            else {
                $secretSigner = $config['validator'][$type]['secretSigner'];
            }
            $initialedSoftConfig['validator'][$type]['secretSigner'] = $secretSigner;
        }
        elseif ($algo == 'RS256') {
            if (!isset($config['validator'][$type]['privateKey'])) {
                if (!isset($defaultConfig['privateKey'])) {
                    $privateKey = null;
                }
                else {
                    $privateKey = $defaultConfig['privateKey'];
                }
            }
            else {
                $privateKey = $config['validator'][$type]['privateKey'];
            }
            if (!isset($config['validator'][$type]['publicKey'])) {
                if (!isset($defaultConfig['publicKey'])) {
                    $publicKey = null;
                }
                else {
                    $publicKey = $defaultConfig['publicKey'];
                }
            }
            else {
                $publicKey = $config['validator'][$type]['publicKey'];
            }
            $initialedSoftConfig['validator'][$type]['publicKey'] = $publicKey;
            $initialedSoftConfig['validator'][$type]['privateKey'] = $privateKey;
        }

        if (!isset($config['validator'][$type]['ttl'])) {
            if (!isset($defaultConfig['ttl'])) {
                $ttl = 180;
            }
            else {
                $ttl = $defaultConfig['ttl'];
            }
        }
        else {
            $ttl = $config['validator'][$type]['ttl'];
        }
        $initialedSoftConfig['validator'][$type]['ttl'] = $ttl;

        if (!isset($config['state'])) {
            if (!isset($defaultConfig['state'])) {
                $state = false;
            }
            else {
                $state = $defaultConfig['state'];
            }
        }
        else {
            $state = $config['state'];
        }
        $initialedSoftConfig['state'] = $state;

        if (!isset($config['headerMetaData'])) {
            if (!isset($defaultConfig['headerMetaData'])) {
                $headerMetaData = false;
            }
            else {
                $headerMetaData = $defaultConfig['headerMetaData'];
            }
        }
        else {
            $headerMetaData = $config['headerMetaData'];
        }
        if (!is_array($headerMetaData)) {
            $headerMetaData = [];
        }
        $initialedSoftConfig['headerMetaData'] = $headerMetaData;

        if (!isset($config['databaseClaims'])) {
            if (!isset($defaultConfig['databaseClaims'])) {
                $databaseClaims = false;
            }
            else {
                $databaseClaims = $defaultConfig['databaseClaims'];
            }
        }
        else {
            $databaseClaims = $config['databaseClaims'];
        }
        if (!is_array($databaseClaims)) {
            $databaseClaims = [];
        }
        $initialedSoftConfig['databaseClaims'] = $databaseClaims;

        if (!isset($config['bodyMetaData'])) {
            if (!isset($defaultConfig['bodyMetaData'])) {
                $bodyMetaData = false;
            }
            else {
                $bodyMetaData = $defaultConfig['bodyMetaData'];
            }
        }
        else {
            $bodyMetaData = $config['bodyMetaData'];
        }
        if (!is_array($bodyMetaData)) {
            $bodyMetaData = [];
        }
        $initialedSoftConfig['bodyMetaData'] = $bodyMetaData;
        if (!isset($config['queryStringMetaData'])) {
            if (!isset($defaultConfig['queryStringMetaData'])) {
                $queryStringMetaData = false;
            }
            else {
                $queryStringMetaData = $defaultConfig['queryStringMetaData'];
            }
        }
        else {
            $queryStringMetaData = $config['queryStringMetaData'];
        }
        if (!is_array($queryStringMetaData)) {
            $queryStringMetaData = [];
        }
        $initialedSoftConfig['queryStringMetaData'] = $queryStringMetaData;

        return $initialedSoftConfig;
    }


}
