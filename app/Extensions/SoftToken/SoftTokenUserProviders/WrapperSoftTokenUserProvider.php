<?php

namespace App\Extensions\SoftToken\SoftTokenUserProviders;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;

class WrapperSoftTokenUserProvider implements UserProvider
{
    /**
     * The user provider instance.
     *
     * @var \Illuminate\Contracts\Auth\UserProvider
     */
    protected UserProvider $provider;
    /**
     * The user provider name.
     *
     * @var string
     */
    protected string $providerName;

    /**
     * Create a new passport user provider.
     *
     * @param  \Illuminate\Contracts\Auth\UserProvider  $provider
     * @param string $providerName
     * @return void
     */
    public function __construct(UserProvider $provider, string $providerName)
//    public function __construct()
    {
        $this->provider = $provider;
        $this->providerName = $providerName;
    }

    public function SoftTokenUserProvider(): static
    {
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function retrieveById($identifier): ?Authenticatable
    {
        return $this->provider->retrieveById($identifier);
    }

    /**
     * {@inheritdoc}
     */
    public function retrieveByToken($identifier, $token): ?Authenticatable
    {
        return $this->provider->retrieveByToken($identifier, $token);
    }

    /**
     * {@inheritdoc}
     */
    public function updateRememberToken(Authenticatable $user, $token): void
    {
        $this->provider->updateRememberToken($user, $token);
    }

    /**
     * {@inheritdoc}
     */
    public function retrieveByCredentials(array $credentials): ?Authenticatable
    {
        return $this->provider->retrieveByCredentials($credentials);
    }

    /**
     * {@inheritdoc}
     */
    public function validateCredentials(Authenticatable $user, array $credentials): bool
    {
        return $this->provider->validateCredentials($user, $credentials);
    }

    /**
     * {@inheritdoc}
     */
    public function rehashPasswordIfRequired(Authenticatable $user, array $credentials, bool $force = false): void
    {
        $this->provider->rehashPasswordIfRequired($user, $credentials, $force);
    }

    /**
     * Get the name of the user provider.
     *
     * @return string
     */
    public function getProviderName(): string
    {
        return $this->providerName;
    }
}
