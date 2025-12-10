<?php

use Xgrug\LaravelGmCrypto\Facades\GmCrypto;

describe('GmCrypto Facade', function () {

    test('facade is accessible', function () {
        expect(GmCrypto::class)->toBeString();
    });

    test('can access sm3 driver through facade', function () {
        $driver = GmCrypto::driver('sm3');

        expect($driver)->toBeInstanceOf(\Xgrug\LaravelGmCrypto\SM3::class);
    });

    test('can access sm4 driver through facade', function () {
        $driver = GmCrypto::driver('sm4');

        expect($driver)->toBeInstanceOf(\Xgrug\LaravelGmCrypto\SM4::class);
    });
});

describe('GmCrypto Facade SM3 Operations', function () {

    test('can hash through facade', function () {
        $hash = GmCrypto::sm3Hash('test');

        expect($hash)
            ->toBeString()
            ->toHaveLength(64);
    });

    test('can create hmac through facade', function () {
        $hmac = GmCrypto::sm3Hmac('message', 'secret');

        expect($hmac)
            ->toBeString()
            ->toHaveLength(64);
    });

    test('can verify through facade', function () {
        $message = 'verify me';
        $hash = GmCrypto::sm3Hash($message);

        expect(GmCrypto::sm3Verify($message, $hash))->toBeTrue();
    });

    test('facade hash matches direct class hash', function () {
        $message = 'consistency test';

        $facadeHash = GmCrypto::sm3Hash($message);
        $directHash = (new \Xgrug\LaravelGmCrypto\SM3())->hash($message);

        expect($facadeHash)->toBe($directHash);
    });
});

describe('GmCrypto Facade SM4 Operations', function () {

    test('can encrypt through facade', function () {
        $encrypted = GmCrypto::sm4Encrypt('secret');

        expect($encrypted)
            ->toBeString()
            ->not->toBe('secret');
    });

    test('can decrypt through facade', function () {
        $plaintext = 'my secret';
        $encrypted = GmCrypto::sm4Encrypt($plaintext);
        $decrypted = GmCrypto::sm4Decrypt($encrypted);

        expect($decrypted)->toBe($plaintext);
    });

    test('can encrypt hex through facade', function () {
        $encrypted = GmCrypto::sm4EncryptHex('data');

        expect($encrypted)->toMatch('/^[0-9a-f]+$/');
    });

    test('can decrypt hex through facade', function () {
        $plaintext = 'hex data';
        $encrypted = GmCrypto::sm4EncryptHex($plaintext);
        $decrypted = GmCrypto::sm4DecryptHex($encrypted);

        expect($decrypted)->toBe($plaintext);
    });

    test('facade handles chinese characters', function () {
        $plaintext = '测试中文字符';
        $encrypted = GmCrypto::sm4Encrypt($plaintext);
        $decrypted = GmCrypto::sm4Decrypt($encrypted);

        expect($decrypted)->toBe($plaintext);
    });

    test('facade handles long text', function () {
        $plaintext = str_repeat('Long text test. ', 100);
        $encrypted = GmCrypto::sm4Encrypt($plaintext);
        $decrypted = GmCrypto::sm4Decrypt($encrypted);

        expect($decrypted)->toBe($plaintext);
    });
});

describe('GmCrypto Facade Integration', function () {

    test('can chain multiple operations', function () {
        $data = 'chain test';

        // Encrypt with SM4
        $encrypted = GmCrypto::sm4Encrypt($data);

        // Create hash of encrypted data with SM3
        $hash = GmCrypto::sm3Hash($encrypted);

        // Decrypt
        $decrypted = GmCrypto::sm4Decrypt($encrypted);

        // Verify
        expect($decrypted)->toBe($data)
            ->and($hash)->toHaveLength(64);
    });

    test('can use different drivers alternately', function () {
        $plaintext = 'alternate test';

        // Use SM4
        $encrypted = GmCrypto::driver('sm4')->encryptBase64($plaintext);

        // Use SM3
        $hash = GmCrypto::driver('sm3')->hash($plaintext);

        // Use SM4 again
        $decrypted = GmCrypto::driver('sm4')->decryptBase64($encrypted);

        expect($decrypted)->toBe($plaintext)
            ->and($hash)->toHaveLength(64);
    });

    test('facade operations are consistent', function () {
        $data = 'consistency';

        // Multiple encryptions should be consistent with same key/IV
        $encrypted1 = GmCrypto::sm4Encrypt($data);
        $encrypted2 = GmCrypto::sm4Encrypt($data);

        $decrypted1 = GmCrypto::sm4Decrypt($encrypted1);
        $decrypted2 = GmCrypto::sm4Decrypt($encrypted2);

        expect($decrypted1)->toBe($data)
            ->and($decrypted2)->toBe($data);
    });
});