<?php

namespace App\Extensions;

use App\Models\Extensions\Scope;

class Soft
{
    /**
     * All of the scopes defined for the application.
     *
     * @var array
     */
    public static array $scopes = [
        //
    ];
    /**
     * The name for API token cookies.
     *
     * @var string
     */
    public static string $cookie = 'laravel_token';
    /**
     * The access token entity class name.
     *
     * @var string
     */
    public static string $accessTokenEntity = 'Laravel\Models\AccessToken';
//    public static string $accessTokenEntity = 'Laravel\Extensions\AccessToken';
    /**
     * The personal access client model class name.
     *
     * @var string
     */
    public static string $personalAccessClientModel = 'Laravel\Models\PersonalAccessClient';
//    public static string $personalAccessClientModel = 'Laravel\Extensions\PersonalAccessClient';
    /**
     * The token model class name.
     *
     * @var string
     */
    public static string $tokenModel = 'Laravel\Models\Token';
//    public static string $tokenModel = 'Laravel\Extensions\Token';
    /**
     * Set the default scope(s). Multiple scopes may be an array or specified delimited by spaces.
     *
     * @param array|string $scope
     * @return void
     */
    public static function setDefaultScope(array|string $scope): void
    {
        static::$defaultScope = is_array($scope) ? implode(' ', $scope) : $scope;
    }
    /**
     * Get all of the defined scope IDs.
     *
     * @return array
     */
    public static function scopeIds(): array
    {
        return static::scopes()->pluck('id')->values()->all();
    }
    /**
     * Determine if the given scope has been defined.
     *
     * @param string $id
     * @return bool
     */
    public static function hasScope(string $id): bool
    {
        return $id === '*' || array_key_exists($id, static::$scopes);
    }
    /**
     * Get all of the scopes defined for the application.
     *
     * @return \Illuminate\Support\Collection
     */
    public static function scopes(): \Illuminate\Support\Collection
    {
        return collect(static::$scopes)->map(function ($description, $id) {
            return new Scope($id, $description); // todo
        })->values();
    }
    /**
     * Get all of the scopes matching the given IDs.
     *
     * @param  array  $ids
     * @return array
     */
    public static function scopesFor(array $ids): array
    {
        return collect($ids)->map(function ($id) {
            if (isset(static::$scopes[$id])) {
                return new Scope($id, static::$scopes[$id]); // todo
            }
        })->filter()->values()->all();
    }
    /**
     * Define the scopes for the application.
     *
     * @param  array  $scopes
     * @return void
     */
    public static function tokensCan(array $scopes): void
    {
        static::$scopes = $scopes;
    }
    /**
     * Get or set the name for API token cookies.
     *
     * @param string|null $cookie
     * @return string|static
     */
    public static function cookie(string $cookie = null): string|static
    {
        if (is_null($cookie)) {
            return static::$cookie;
        }

        static::$cookie = $cookie;

        return new static;
    }


}
