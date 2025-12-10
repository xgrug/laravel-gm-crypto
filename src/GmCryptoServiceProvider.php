<?php


namespace Xgrug\LaravelGmCrypto;

use Illuminate\Support\ServiceProvider;

class GmCryptoServiceProvider extends ServiceProvider
{
    /**
     * 注册服务
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/gmcrypto.php', 'gmcrypto'
        );

        $this->app->singleton('gmcrypto', function ($app) {
            return new GmCryptoManager($app);
        });

        $this->app->alias('gmcrypto', GmCryptoManager::class);
    }

    /**
     * 启动服务
     */
    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/gmcrypto.php' => config_path('gmcrypto.php'),
            ], 'gmcrypto-config');
        }
    }

    /**
     * 获取提供的服务
     */
    public function provides(): array
    {
        return ['gmcrypto', GmCryptoManager::class];
    }
}