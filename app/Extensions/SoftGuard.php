<?php

namespace App\Extensions;

use App\Models\Models\User;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;

use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use JetBrains\PhpStorm\NoReturn;
use phpseclib3\Math\PrimeField\Integer;
use Symfony\Component\HttpFoundation\InputBag;

class SoftGuard implements Guard
{
    use GuardHelpers;

    // check() // have
    // guest() // have
    // id() // have
    // hasUser() // have
    // setUser(AuthenticatableContract $user) // have
    // authenticate()
    // forgetUser()
    // getProvider()
    // setProvider(UserProvider $provider)


    private Request $request;
    private array $config;
    private array $defaultConfig;

    public function __construct(
        UserProvider $provider,
        Request      $request,
                     $configuration
    )
    {
        $this->provider = $provider;
        $this->request = $request;
        $this->config = $configuration;
        $this->defaultConfig = Config::get('soft');
        $this->initialSoftConfig();
//        $token = $this->request->bearerToken();
    }

    private function initialSoftConfig(): void
    {
        if (!isset($this->config['validator'])) {
            $this->config = array_merge($this->config, [
                'validator' => [],
            ]);
        }

        if (!key($this->config['validator'])) {
            $type = 'headers';
        }
        else {
            $type = key($this->config['validator']);
        }

        if (!isset($this->config['validator'][$type]['keyword'])) {
            $this->config['validator'][$type]['keyword'] = 'Authorization';
        }
        if (!isset($this->config['validator'][$type]['prefix'])) {
            $this->config['validator'][$type]['prefix'] = 'Bearer';
        }

        if (!isset($this->config['validator'][$type]['algo'])) {
            if (!isset($this->defaultConfig['algo'])) {
                $algo = 'HS256';
            }
            else {
                $algo = $this->defaultConfig['algo'];
            }
        }
        else {
            $algo = $this->config['validator'][$type]['algo'];
        }
        $this->config['validator'][$type]['algo'] = $algo;

        if ($algo == 'HS256') {
            if (!isset($this->config['validator'][$type]['secretSigner'])) {
                if (!isset($this->defaultConfig['secretSigner'])) {
                    $secretSigner = null;
                }
                else {
                    $secretSigner = $this->defaultConfig['secretSigner'];
                }
            }
            else {
                $secretSigner = $this->config['validator'][$type]['secretSigner'];
            }
            $this->config['validator'][$type]['secretSigner'] = $secretSigner;
        }
        elseif ($algo == 'RS256') {
            if (!isset($this->config['validator'][$type]['privateKey'])) {
                if (!isset($this->defaultConfig['privateKey'])) {
                    $privateKey = null;
                }
                else {
                    $privateKey = $this->defaultConfig['privateKey'];
                }
            }
            else {
                $privateKey = $this->config['validator'][$type]['privateKey'];
            }
            if (!isset($this->config['validator'][$type]['publicKey'])) {
                if (!isset($this->defaultConfig['publicKey'])) {
                    $publicKey = null;
                }
                else {
                    $publicKey = $this->defaultConfig['publicKey'];
                }
            }
            else {
                $publicKey = $this->config['validator'][$type]['publicKey'];
            }
            $this->config['validator'][$type]['publicKey'] = $publicKey;
            $this->config['validator'][$type]['privateKey'] = $privateKey;
        }

        if (!isset($this->config['validator'][$type]['ttl'])) {
            if (!isset($this->defaultConfig['ttl'])) {
                $ttl = 180;
            }
            else {
                $ttl = $this->defaultConfig['ttl'];
            }
        }
        else {
            $ttl = $this->config['validator'][$type]['ttl'];
        }
        $this->config['validator'][$type]['ttl'] = $ttl;

        if (!isset($this->config['state'])) {
            if (!isset($this->defaultConfig['state'])) {
                $state = false;
            }
            else {
                $state = $this->defaultConfig['state'];
            }
        }
        else {
            $state = $this->config['state'];
        }
        $this->config['state'] = $state;

        if (!isset($this->config['headerMetaData'])) {
            if (!isset($this->defaultConfig['headerMetaData'])) {
                $headerMetaData = false;
            }
            else {
                $headerMetaData = $this->defaultConfig['headerMetaData'];
            }
        }
        else {
            $headerMetaData = $this->config['headerMetaData'];
        }
        if (!is_array($headerMetaData)) {
            $headerMetaData = [];
        }
        $this->config['headerMetaData'] = $headerMetaData;

        if (!isset($this->config['databaseClaims'])) {
            if (!isset($this->defaultConfig['databaseClaims'])) {
                $databaseClaims = false;
            }
            else {
                $databaseClaims = $this->defaultConfig['databaseClaims'];
            }
        }
        else {
            $databaseClaims = $this->config['databaseClaims'];
        }
        if (!is_array($databaseClaims)) {
            $databaseClaims = [];
        }
        $this->config['databaseClaims'] = $databaseClaims;

        if (!isset($this->config['bodyMetaData'])) {
            if (!isset($this->defaultConfig['bodyMetaData'])) {
                $bodyMetaData = false;
            }
            else {
                $bodyMetaData = $this->defaultConfig['bodyMetaData'];
            }
        }
        else {
            $bodyMetaData = $this->config['bodyMetaData'];
        }
        if (!is_array($bodyMetaData)) {
            $bodyMetaData = [];
        }
        $this->config['bodyMetaData'] = $bodyMetaData;
        if (!isset($this->config['queryStringMetaData'])) {
            if (!isset($this->defaultConfig['queryStringMetaData'])) {
                $queryStringMetaData = false;
            }
            else {
                $queryStringMetaData = $this->defaultConfig['queryStringMetaData'];
            }
        }
        else {
            $queryStringMetaData = $this->config['queryStringMetaData'];
        }
        if (!is_array($queryStringMetaData)) {
            $queryStringMetaData = [];
        }
        $this->config['queryStringMetaData'] = $queryStringMetaData;
//        dd($this->config);
    }

///////////////////////////////////////////////////////////////////

    public function getTokenForRequest(): ?string
    {
        if (!isset($this->config['validator'])) {
            return null;
        }
        $type = key($this->config['validator']);
        $keyWord = $this->config['validator'][$type]['keyword'];
        $prefix = $this->config['validator'][$type]['prefix'];

        if ($type === 'headers') {
            $token = $this->GetTokenFromRequestHeader($keyWord, $prefix);
        }
        elseif ($type === 'RouteParams') {
//            $RouteParamToken
            $token = $this->GetTokenFromRequestRouteParams($keyWord);
        }
        elseif ($type === 'QueryStrings') {
//            $QueryStringsToken
            $token = $this->GetTokenFromRequestQueryStrings($keyWord);
        }
        elseif ($type === 'Cookies') {
//            $CookiesToken
            $token = $this->GetTokenFromRequestCookies($keyWord);
        }

//        if (empty($token)) {
//            $token = $this->request->bearerToken();
//        }


        return $token;
    }

    function GetTokenFromRequestHeader($keyWord, $prefix)
    {
        $header = $this->request->header($keyWord, '');
        $position = strrpos($header, $prefix . ' ');
        if ($position !== false) {
            $header = substr($header, $position + 7);
            $value = str_contains($header, ',') ? strstr($header, ',', true) : $header;
            return $value;
        }

    }

    private function logicSoftTokenAuthenticate($token): ?int
    {
//        $algo = $this->config['validator'][$type]['algo'];
//        $ttl = $this->config['validator'][$type]['ttl'];
        // check have config also read from default config file
        $type = key($this->config['validator']);
        $secretSigner = $this->config['validator'][$type]['secretSigner'];
        $softToken = new SoftToken();

//            $claims['claims'] = [
//                'iss' => 'http://example.org',
//                'aud' => 'http://example.com',
//                'iat' => 1356999524,
//                'nbf' => 1357000000,
////                'exp' => 1000000000,
//            ];
//            $tokenString = $softToken->makeTokenString($secretSigner , $claims);
//            dd($softToken,$tokenString);
////            $test = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vZXhhbXBsZS5vcmciLCJhdWQiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJpYXQiOjEzNTY5OTk1MjQsIm5iZiI6MTM1NzAwMDAwMH0.IbjnVGXlzHuTIQHj41WPa9biWIfdFKfb3PlMzJtzBGE';
////            $softToken->TokenStringConvertToObject($secretSigner, $test);
        $softToken->TokenStringConvertToObject($secretSigner, $token);
        if ($softToken->getTokenStatus() != '') {
//            return null; // todo unCommit
        }

        // soft token config set, read from token table
        // is true => // get rel [nameSpace, domain, group, guard, scope, metadata[exp...]]
        if ($this->config['state'] == 'database') {
//            $token = Token::where();
//            dd($this->config['state']);
        }
        // soft token config set, read metadata from request header
        // is true => // get (header or any) check if in token claims
        if ($this->config['headerMetaData'] != null) {
            foreach ($this->config['headerMetaData'] as $key => $val) {
                if ($this->request->header($key) != $softToken->publicClaims[$val]) {
                    return null;
                }
            }
        }
        // soft token config set, read metadata from request body
        // is true => // get (body or any) check if in token claims
        if ($this->config['bodyMetaData'] != null) {
            foreach ($this->config['bodyMetaData'] as $key => $val) {
                if ($this->request->post($key) != $softToken->publicClaims[$val]) {
                    return null;
                }
            }
        }
        // soft token config set, read metadata from request queryString
        // is true => // get (queryString or any) check if in token claims
        if ($this->config['queryStringMetaData'] != null) {
            foreach ($this->config['queryStringMetaData'] as $key => $val) {
                if ($this->request->query($key) != $softToken->publicClaims[$val]) {
                    return null;
                }
            }
        }
        // soft token config set, read metadata from request cookie
        // is true => // get (queryString or any) check if in token claims
        if ($this->config['cookieMetaData'] != null) {
            foreach ($this->config['cookieMetaData'] as $key => $val) {
                $cookieMetaData = ''; // todo
                if ($cookieMetaData != $softToken->publicClaims[$val]) {
                    return null;
                }
            }
        }
        // soft token config set, equal metadata from request with table
        // is true => // get token claims check if in table
        if ($this->config['databaseClaims'] != null) {
            foreach ($this->config['databaseClaims'] as $key => $val) {
                $id = $softToken->publicClaims[$key];
                $column = 'id';
                if (is_array($val)) {
                    $column = $val[1];
                    $val = $val[0];
                }
                $model = '\App\Models\\' . $val;
                $res = $model::where($column, '=', $id)->first();
                if ($res == null) {
                    return null;
                }
            }
        }
        $sub = $softToken->getSubjectIdentifier();

        return (int)$sub;
//            dd($sub, $softToken, $this->provider->retrieveById($sub));

//            $payloads = $softToken->GetTokenPayloads($token, $secretSigner);
//            dd($softToken->GetTokenPayloads($token, $secretSigner));
//            dd($softToken->setTokenExpiration(15));
//            $softToken->setTokenPayloads($payloads, $secretSigner);
    }







///////////////////////////////////////////////////////////////////
    /**
     * @inheritDoc
     *
     * @return Authenticatable|null
     */
    public function user(): ?Authenticatable // not in helper
    {
        if (!is_null($this->user)) {
            return $this->user;
        }
        $token = $this->getTokenForRequest();

        if (!empty($token)) {
            $subjectId = $this->logicSoftTokenAuthenticate($token);
            $this->user = $this->provider->retrieveById($subjectId); // modelUserProvider
            // $this->user->with('Token')
            return $this->user;
        }
        return null;
    }

    /**
     * @inheritDoc
     *
     * @return bool
     */
    public function check()
    {
        // TODO: Implement check() method.
    }

    /**
     * @inheritDoc
     */
    public function guest()
    {
        // TODO: Implement guest() method.
    }

    /**
     * @inheritDoc
     */
    public function id()
    {
        // TODO: Implement id() method.
    }

    /**
     * @inheritDoc
     */
    public function validate(array $credentials = []) // not in helper
    {
        // TODO: Implement validate() method.
    }

    /**
     * @inheritDoc
     */
    public function hasUser()
    {
        // TODO: Implement hasUser() method.
    }

    /**
     * @inheritDoc
     */
    public function setUser(Authenticatable $user)
    {
        // TODO: Implement setUser() method.
    }
}
