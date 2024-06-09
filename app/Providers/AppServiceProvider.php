<?php

namespace App\Providers;

//use App\Extensions\SoftGuard;
use App\Extensions\SoftToken\SoftGuard;

//use Illuminate\Auth\EloquentUserProvider;
//use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\File;
use Illuminate\Support\ServiceProvider;

use Illuminate\Contracts\Foundation\Application;
use Laravel\Passport\Passport;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
//        dd(__DIR__ . '/oauth');
        //
//        Passport::loadKeysFrom(__DIR__ );
        Passport::personalAccessTokensExpireIn(now()->addMonths(6));
        //
        Auth::extend('soft', function (Application $app, string $name, array $config) {
//            dd($app,$name,$config);
            // Return an instance of Illuminate\Contracts\Auth\Guard...
            if (isset($config['userProvider'])) {
//                $exists = File::exists(App_path('SoftToken\SoftTokenUserProviders\\'.$config['userProvider'].'.php'));
                $exists = File::exists(App_path('Extensions\SoftToken\SoftTokenUserProviders\\' . $config['userProvider'] . '.php'));
//                $userProviderName = '\App\SoftToken\SoftTokenUserProviders\\' . $config['userProvider'];
                $userProviderName = '\App\Extensions\SoftToken\SoftTokenUserProviders\\' . $config['userProvider'];
//                $classUserProvider = '\App\SoftToken\SoftTokenUserProviders\\' . $config['userProvider'];
                $classUserProvider = '\App\Extensions\SoftToken\SoftTokenUserProviders\\' . $config['userProvider'];
                if ($exists) {
                    try {
                        $modelProvider = \Illuminate\Support\Facades\App::make($classUserProvider);
                    }
                    catch (\Exception $ex){
//                        $ex->getMessage();
//                    $modelProvider = new \App\SoftToken\SoftTokenUserProviders\WrapperSoftTokenUserProvider(Auth::createUserProvider($config['provider']), $config['provider']);
                    $modelProvider = (new \App\Extensions\SoftToken\SoftTokenUserProviders\WrapperSoftTokenUserProvider(Auth::createUserProvider($config['provider']), $config['provider']));
//                    $modelProvider = (new \App\Extensions\SoftToken\SoftTokenUserProviders\WrapperSoftTokenUserProvider(Auth::createUserProvider($config['provider']), $config['provider']))->SoftTokenUserProvider();
                    }
                }
                else {
                    $modelProvider = Auth::createUserProvider($config['provider']);
                }
            }
            else {
                $modelProvider = Auth::createUserProvider($config['provider']);
            }
            $request = app('request');
            $guard = new SoftGuard($modelProvider, $request, $config);
//            dd($guard);
            return $guard;
        });

    }
}
