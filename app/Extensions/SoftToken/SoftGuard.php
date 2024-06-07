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
    public static array $StatefulDrivers = [
        'Default' => "", // Eloquent
        'Database' => "\App\Extensions\SoftToken\SoftTokenStatefulDrivers\SoftTokenStatefulDriversDefault",
    ];

    public static array $RequestCheckerMethodologies = [
        'headersMetaData' => "\App\Extensions\SoftToken\SoftTokenRequestCheckerMethodologies\SoftTokenRequestCheckerHeader",
        'routeParamsMetaData' => "\App\Extensions\SoftToken\SoftTokenRequestCheckerMethodologies\SoftTokenRequestCheckerRouteParams",
        'queryStringsMetaData' => "\App\Extensions\SoftToken\SoftTokenRequestCheckerMethodologies\SoftTokenRequestCheckerQueryString",
        'cookiesMetaData' => "\App\Extensions\SoftToken\SoftTokenRequestCheckerMethodologies\SoftTokenRequestCheckerCookie",
    ];

    public static string $SoftTokenStoredDataChecker = "\App\Extensions\SoftToken\SoftTokenReadStoreMoreData\SoftTokenStoredDataChecker";
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
//        dd($this->config);
//        dd($this->request);
//        $this->initialSoftConfig();
//        $token = $this->request->bearerToken();
    }

    //////////////////////////////////////////////
    public function RequestReader($config): SoftTokenIdentified
    {
        $result = new SoftTokenIdentified();
        if (!in_array(key($config['validator']), array_keys(self::$requestReaders))) {
            $result->identifyStatus = 'The Request Validator Not Match request Readers.';
            $result->setIdentifyStatusLogs($result->identifyStatus, 'RequestReader');
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

    public function StateDrivers($softTokenIdentify)
    {
        if (($this->config['state']['driver'] == 'stateless') or ($this->config['state'] == null)) {
//            $softTokenIdentify->AccessTokenEntityData = [];
            $AccessTokenEntityData = [];
        }
        else {
            if (isset(self::$StatefulDrivers[$this->config['state']['driver']])) {
                $statefulDrivers = new self::$StatefulDrivers[$this->config['state']['driver']](
                    $softTokenIdentify,
                    $this->config['state']['identifyCondition']
                // or
//                    [
//                        'select' => ['id', 'name', 'tokenable_type', 'tokenable_id', 'token', 'expires_at'],
//                        'where' =>
//                            [
//                                'one' => [
//                                    'id' => $softTokenIdentify->AccessTokenID,
////                                    'id' => 'AccessTokenID',
//                                    'token' => $softTokenIdentify->AccessToken,
////                                    'token' => 'AccessToken'
////                                    'name' => $softTokenIdentify->AccessTokenEntityData['name'],
//////                                    'name' => 'AccessTokenName' // todo
//                                ],
//                                'two' => [
//                                    'tokenable_type' => $softTokenIdentify->getProviderModelName(),
//                                    'tokenable_id' => $softTokenIdentify->getProviderModelID(),
////                                    'tokenable_type' => 'providerModelName',
////                                    'tokenable_id' => 'providerModelID',
//                                ],
//                            ]
//                    ]
                );
                $AccessTokenEntityData = $statefulDrivers->loadTokenData();
            }
            else {
                $accessToken = $softTokenIdentify->AccessToken;
                $tokenEntity = self::$tokenModel::where('token', '=', $accessToken)
                    ->first();
                if (!$tokenEntity) {
//                    $softTokenIdentify->AccessTokenEntityData = [];
                    $AccessTokenEntityData = [];
                }
                else {
//                    $softTokenIdentify->AccessTokenEntityData = $tokenEntity->toArray();
                    $AccessTokenEntityData = $tokenEntity->toArray();
                }
//                \App\Models\Token::where('id', '=', $Identified->AccessTokenID)->first();
            }
        }
        if (empty($AccessTokenEntityData)) {
            $message = 'AccessTokenEntityData Not Found .';
            $softTokenIdentify->setIdentifyStatusLogs($message, 'StateDrivers');
            $softTokenIdentify->AccessTokenEntityData = $AccessTokenEntityData;
            $softTokenIdentify->AccessTokenName = null;
        }
        else {
            $softTokenIdentify->setIdentifyStatusLogs(null, 'StateDrivers');
            $softTokenIdentify->AccessTokenEntityData = $AccessTokenEntityData;
            $softTokenIdentify->AccessTokenName = $AccessTokenEntityData['name'];;
        }
        return $softTokenIdentify;
    }

    public function RequestChecker($config, $softTokenIdentify)
    {
        foreach (self::$RequestCheckerMethodologies as $key => $value) {
            if (!empty($config['requestChecker'][$key])) {
                if (in_array($key, array_keys($config['requestChecker']))) {
                    $MetaData = $config['requestChecker'][$key];
                    $requestChecker = new self::$RequestCheckerMethodologies[$key](
                        $MetaData,
                        $this->request,
                        $softTokenIdentify,
                    );
                    $requestChecker->getCheckAbleData();
                    if ($requestChecker->matchDataStatus != null) {
                        $softTokenIdentify->identifyStatus = $requestChecker->matchDataStatus;
                        $softTokenIdentify->setIdentifyStatusLogs($requestChecker->getMatchData(), 'RequestChecker ' . $key);
                    }
                    else {
                        $softTokenIdentify->identifyStatus = null;
                        $softTokenIdentify->setIdentifyStatusLogs(null, 'RequestChecker ' . $key);
                    }
                }
                else {
                    $message = 'Can not found RequestCheckerMethodology: '.' for check request.';
                    $softTokenIdentify->identifyStatus = $message;
                    $softTokenIdentify->setIdentifyStatusLogs($message, 'RequestChecker ' . $key);
                }
            }
            else {
                $softTokenIdentify->identifyStatus = null;
                $softTokenIdentify->setIdentifyStatusLogs(null, 'RequestChecker ' . $key);
            }
        }
        return $softTokenIdentify;
//////////////////////////////////////////
        /*
        foreach ($config['requestChecker'] as $key => $item){
            $MetaData = $config['requestChecker'][$key];
            $requestChecker = new self::$RequestCheckerMethodologies[$key](
                $MetaData,
                $this->request,
                $softTokenIdentify,
            );
            $requestChecker->getCheckAbleData();
            if($requestChecker->matchDataStatus != null){
                $softTokenIdentify->identifyStatus = $requestChecker->matchDataStatus;
                // $this->errorLogArrayPush()
                return $softTokenIdentify;
                break;
            }
        }
        return $softTokenIdentify;
        */
    }

    public function StoredDataChecker($config, $softTokenIdentify)
    {
        $softTokenStoredData = new self::$SoftTokenStoredDataChecker($config['storedDataChecker'], $softTokenIdentify);
        $softTokenStoredData->getMatchData();
        $softTokenIdentify->identifyStatus = $softTokenStoredData->matchDataStatus;
        $softTokenIdentify->setIdentifyStatusLogs($softTokenStoredData->getMatchData(), 'StoredDataChecker');
        return $softTokenIdentify;
    }

    public function ReadStoredData($config, $softTokenIdentify)
    {
        dd($config, $softTokenIdentify);
        // get token relational and provider (user)
        $softTokenIdentify->ProviderModelEntityData = [];
        $softTokenIdentify->MoreModelEntityData = [];
        return $softTokenIdentify;
    }
    //////////////////////////////////////////////

    public function user(): ?Authenticatable
    {
        $softTokenIdentify = $this->RequestReader($this->config);
        $softTokenIdentify = $this->StateDrivers($softTokenIdentify);
        $softTokenIdentify = $this->RequestChecker($this->config, $softTokenIdentify);
        $softTokenIdentify = $this->StoredDataChecker($this->config, $softTokenIdentify);
        // add cookie checker
        $softTokenIdentify = $this->ReadStoredData($this->config, $softTokenIdentify);
//dd(
//    $this->request->input('link'),
//    $this->request->cookie('SoftTokenCookie'),
//    $this->request->cookies,
//    $this->request,
//);

        dd($softTokenIdentify);
        if ($softTokenIdentify->identifyStatus != null) {
            return null;
        }
        $this->user = $this->provider->retrieveById($softTokenIdentify['providerModelID']);
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
        // try exception config problem
        //////////////////////
        if (!isset($config['driver'])) {
            $initialedSoftConfig['driver'] = 'soft';
        }
        else {
            $initialedSoftConfig['driver'] = $config['driver'];
        }

        //////////////////////
        if (!isset($config['provider'])) {
            $initialedSoftConfig['provider'] = 'users';
        }
        else {
            $initialedSoftConfig['provider'] = $config['provider'];
        }

        //////////////////////
        if (!isset($config['validator'])) {
            $initialedSoftConfig = array_merge($config, [
                'validator' => [],
            ]);
        }

        //////////////////////
        if (!key($config['validator'])) {
            $type = 'headers';
        }
        else {
            $type = key($config['validator']);
        }

        //////////////////////
        if (!isset($config['validator'][$type]['keyword'])) { // todo check array
            $initialedSoftConfig['validator'][$type]['keyword'] = 'Authorization';
        }
        else {
            $initialedSoftConfig['validator'][$type]['keyword'] = $config['validator'][$type]['keyword'];
        }

        //////////////////////
        if (!isset($config['validator'][$type]['prefix'])) { // todo check array
            $initialedSoftConfig['validator'][$type]['prefix'] = 'Bearer';
        }
        else {
            $initialedSoftConfig['validator'][$type]['prefix'] = $config['validator'][$type]['prefix'];
        }

        //////////////////////
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

        //////////////////////
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
        else {
            // todo all type
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

        //////////////////////
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

        //////////////////////
        if (!isset($config['state'])) {
            if (!isset($defaultConfig['state'])) {
                $state = [];
            }
            else {
                $state = $defaultConfig['state'];
            }
        }
        else {
            if (!isset($config['state']['driver'])) {
                $state['driver'] = 'Database';
            }
            else {
                $state['driver'] = $config['state']['driver'];
            }

            if (!isset($config['state']['identifyCondition'])) {
                $state['identifyCondition']['where'] = [
                    ['token' => 'AccessToken',]
                ];
            }
            else {
                if (empty($config['state']['identifyCondition'])) {
                    $state['identifyCondition']['where'] = [
                        ['token' => 'AccessToken',]
                    ];
                }
                else {
                    $state['identifyCondition'] = $config['state']['identifyCondition'];
                }
            }
        }
        $initialedSoftConfig['state'] = $state;

        //////////////////////
        if (!isset($config['requestChecker'])) {
            $requestChecker = [
                'headersMetaData' => [],
                'routeParamsMetaData' => [],
                'queryStringsMetaData' => [],
                'cookiesMetaData' => [],
            ];
        }
        else {
            $requestChecker = [
                'headersMetaData' => [],
                'routeParamsMetaData' => [],
                'queryStringsMetaData' => [],
                'cookiesMetaData' => [],
            ];

            foreach ($requestChecker as $key => $value) {
                if (!isset($config['requestChecker'][$key])) {

                    if (!isset($defaultConfig['requestChecker'][$key])) {
                        $requestChecker[$key] = [];
                    }
                    else {
                        $requestChecker[$key] = $defaultConfig['requestChecker'][$key];
                    }
                }
                else {
                    $requestChecker[$key] = $config['requestChecker'][$key];
                }
            }
        }
        $initialedSoftConfig['requestChecker'] = $requestChecker;

        //////////////////////
        if (!isset($config['storedDataChecker'])) {
            if (!isset($defaultConfig['storedDataChecker'])) {
                $storedDataChecker = [];
            }
            else {
                $storedDataChecker = $defaultConfig['storedDataChecker'];
            }
        }
        else {
            $storedDataChecker = [];
            if(is_array($config['storedDataChecker'])) {
                foreach ($config['storedDataChecker'] as $key => $value) {
                    if (!is_array($value) or (count($value) < 2)) {
                        $storedDataChecker[$key] = [];
                    }
                    else {
                        $storedDataChecker[$key] = $value;
                    }
                }
            }
        }
        $initialedSoftConfig['storedDataChecker'] = $storedDataChecker;

        //////////////////////
        if (!isset($config['databaseMetaDate'])) {
            if (!isset($defaultConfig['databaseMetaDate'])) {
                $databaseMetaDate = false;
            }
            else {
                $databaseMetaDate = $defaultConfig['databaseMetaDate'];
            }
        }
        else {
            $databaseMetaDate = $config['databaseMetaDate'];
        }
        if (!is_array($databaseMetaDate)) {
            $databaseMetaDate = [];
        }
        $initialedSoftConfig['databaseMetaDate'] = $databaseMetaDate;

        //////////////////////
        return $initialedSoftConfig;
    }


}
