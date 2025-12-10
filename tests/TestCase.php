<?php


namespace Xgrug\LaravelGmCrypto\Tests;

use Orchestra\Testbench\TestCase as Orchestra;
use Xgrug\LaravelGmCrypto\GmCryptoServiceProvider;

class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();
    }

    protected function getPackageProviders($app): array
    {
        return [
            GmCryptoServiceProvider::class,
        ];
    }

    protected function getPackageAliases($app): array
    {
        return [
            'GmCrypto' => \Xgrug\LaravelGmCrypto\Facades\GmCrypto::class,
        ];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('gmcrypto.default', 'sm4');
        $app['config']->set('gmcrypto.sm4', [
            'key' => '0123456789abcdeffedcba9876543210',
            'mode' => 'CBC',
            'iv' => 'fedcba98765432100123456789abcdef',
            'padding' => 'pkcs7',
        ]);
        $app['config']->set('gmcrypto.sm3', [
            'hmac' => false,
            'hmac_key' => '',
        ]);
    }
}