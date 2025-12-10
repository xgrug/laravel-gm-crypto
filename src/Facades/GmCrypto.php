<?php

namespace Xgrug\LaravelGmCrypto\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static \Xgrug\LaravelGmCrypto\SM3|\Xgrug\LaravelGmCrypto\SM4 driver(string $driver = null)
 * @method static string sm3Hash(string $message)
 * @method static string sm3Hmac(string $message, string $key)
 * @method static bool sm3Verify(string $message, string $hash)
 * @method static string sm4Encrypt(string $plaintext)
 * @method static string sm4Decrypt(string $ciphertext)
 * @method static string sm4EncryptHex(string $plaintext)
 * @method static string sm4DecryptHex(string $ciphertext)
 *
 * @see \Xgrug\LaravelGmCrypto\GmCryptoManager
 */
class GmCrypto extends Facade
{
    /**
     * 获取 Facade 的注册名称
     */
    protected static function getFacadeAccessor(): string
    {
        return 'gmcrypto';
    }
}