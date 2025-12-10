<?php

use Xgrug\LaravelGmCrypto\GmCryptoManager;
use Xgrug\LaravelGmCrypto\SM3;
use Xgrug\LaravelGmCrypto\SM4;

describe('GmCryptoManager', function () {

    test('can get default driver', function () {
        $manager = app(GmCryptoManager::class);

        expect($manager->getDefaultDriver())->toBe('sm4');
    });

    test('can create sm3 driver', function () {
        $manager = app(GmCryptoManager::class);
        $driver = $manager->driver('sm3');

        expect($driver)->toBeInstanceOf(SM3::class);
    });

    test('can create sm4 driver', function () {
        $manager = app(GmCryptoManager::class);
        $driver = $manager->driver('sm4');

        expect($driver)->toBeInstanceOf(SM4::class);
    });

    test('returns same driver instance on multiple calls', function () {
        $manager = app(GmCryptoManager::class);

        $driver1 = $manager->driver('sm3');
        $driver2 = $manager->driver('sm3');

        expect($driver1)->toBe($driver2);
    });
});

describe('GmCryptoManager SM3 Methods', function () {

    test('can hash using sm3Hash method', function () {
        $manager = app(GmCryptoManager::class);
        $hash = $manager->sm3Hash('test message');

        expect($hash)
            ->toBeString()
            ->toHaveLength(64);
    });

    test('can create hmac using sm3Hmac method', function () {
        $manager = app(GmCryptoManager::class);
        $hmac = $manager->sm3Hmac('message', 'key');

        expect($hmac)
            ->toBeString()
            ->toHaveLength(64);
    });

    test('can verify hash using sm3Verify method', function () {
        $manager = app(GmCryptoManager::class);
        $message = 'test';
        $hash = $manager->sm3Hash($message);

        expect($manager->sm3Verify($message, $hash))->toBeTrue();
    });

    test('sm3Verify returns false for wrong hash', function () {
        $manager = app(GmCryptoManager::class);

        expect($manager->sm3Verify('test', 'wronghash'))->toBeFalse();
    });
});

describe('GmCryptoManager SM4 Methods', function () {

    test('can encrypt using sm4Encrypt method', function () {
        $manager = app(GmCryptoManager::class);
        $plaintext = 'secret data';
        $encrypted = $manager->sm4Encrypt($plaintext);

        expect($encrypted)
            ->toBeString()
            ->not->toBe($plaintext);
    });

    test('can decrypt using sm4Decrypt method', function () {
        $manager = app(GmCryptoManager::class);
        $plaintext = 'secret data';

        $encrypted = $manager->sm4Encrypt($plaintext);
        $decrypted = $manager->sm4Decrypt($encrypted);

        expect($decrypted)->toBe($plaintext);
    });

    test('can encrypt to hex using sm4EncryptHex method', function () {
        $manager = app(GmCryptoManager::class);
        $encrypted = $manager->sm4EncryptHex('test');

        expect($encrypted)->toMatch('/^[0-9a-f]+$/');
    });

    test('can decrypt hex using sm4DecryptHex method', function () {
        $manager = app(GmCryptoManager::class);
        $plaintext = 'hex test';

        $encrypted = $manager->sm4EncryptHex($plaintext);
        $decrypted = $manager->sm4DecryptHex($encrypted);

        expect($decrypted)->toBe($plaintext);
    });

    test('encrypted base64 output is valid', function () {
        $manager = app(GmCryptoManager::class);
        $encrypted = $manager->sm4Encrypt('test');

        expect(base64_decode($encrypted, true))->not->toBeFalse();
    });
});