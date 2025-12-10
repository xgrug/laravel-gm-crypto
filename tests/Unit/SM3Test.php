<?php

use Xgrug\LaravelGmCrypto\SM3;

describe('SM3 Hash Algorithm', function () {

    test('can calculate sm3 hash for empty string', function () {
        $sm3 = new SM3();
        $hash = $sm3->hash('');

        expect($hash)
            ->toBeString()
            ->toHaveLength(64)
            ->toBe('1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b');
    });

    test('can calculate sm3 hash for simple string', function () {
        $sm3 = new SM3();
        $hash = $sm3->hash('abc');

        expect($hash)
            ->toBeString()
            ->toHaveLength(64)
            ->toBe('66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0');
    });

    test('can calculate sm3 hash for hello world', function () {
        $sm3 = new SM3();
        $hash = $sm3->hash('Hello World');

        expect($hash)
            ->toBeString()
            ->toHaveLength(64);
    });

    test('can calculate sm3 hash for chinese characters', function () {
        $sm3 = new SM3();
        $hash = $sm3->hash('你好世界');

        expect($hash)
            ->toBeString()
            ->toHaveLength(64);
    });

    test('can calculate sm3 hash for long string', function () {
        $sm3 = new SM3();
        $longString = str_repeat('a', 1000);
        $hash = $sm3->hash($longString);

        expect($hash)
            ->toBeString()
            ->toHaveLength(64);
    });

    test('same input produces same hash', function () {
        $sm3 = new SM3();
        $input = 'test string';

        $hash1 = $sm3->hash($input);
        $hash2 = $sm3->hash($input);

        expect($hash1)->toBe($hash2);
    });

    test('different inputs produce different hashes', function () {
        $sm3 = new SM3();

        $hash1 = $sm3->hash('input1');
        $hash2 = $sm3->hash('input2');

        expect($hash1)->not->toBe($hash2);
    });

    test('can verify correct hash', function () {
        $sm3 = new SM3();
        $message = 'verify test';
        $hash = $sm3->hash($message);

        expect($sm3->verify($message, $hash))->toBeTrue();
    });

    test('can detect incorrect hash', function () {
        $sm3 = new SM3();
        $message = 'verify test';
        $wrongHash = 'abc123';

        expect($sm3->verify($message, $wrongHash))->toBeFalse();
    });

    test('verification is case insensitive', function () {
        $sm3 = new SM3();
        $message = 'case test';
        $hash = $sm3->hash($message);
        $upperHash = strtoupper($hash);

        expect($sm3->verify($message, $upperHash))->toBeTrue();
    });
});

describe('SM3 HMAC', function () {

    test('can calculate hmac with key', function () {
        $sm3 = new SM3();
        $hmac = $sm3->hmac('message', 'secret-key');

        expect($hmac)
            ->toBeString()
            ->toHaveLength(64);
    });

    test('different keys produce different hmacs', function () {
        $sm3 = new SM3();
        $message = 'test message';

        $hmac1 = $sm3->hmac($message, 'key1');
        $hmac2 = $sm3->hmac($message, 'key2');

        expect($hmac1)->not->toBe($hmac2);
    });

    test('same key and message produce same hmac', function () {
        $sm3 = new SM3();
        $message = 'test message';
        $key = 'secret-key';

        $hmac1 = $sm3->hmac($message, $key);
        $hmac2 = $sm3->hmac($message, $key);

        expect($hmac1)->toBe($hmac2);
    });

    test('can use hmac mode from config', function () {
        $sm3 = new SM3([
            'hmac' => true,
            'hmac_key' => 'config-key'
        ]);

        $hash = $sm3->hash('message');

        expect($hash)
            ->toBeString()
            ->toHaveLength(64);
    });

    test('hmac with empty key', function () {
        $sm3 = new SM3();
        $hmac = $sm3->hmac('message', '');

        expect($hmac)
            ->toBeString()
            ->toHaveLength(64);
    });

    test('hmac with long key', function () {
        $sm3 = new SM3();
        $longKey = str_repeat('k', 100);
        $hmac = $sm3->hmac('message', $longKey);

        expect($hmac)
            ->toBeString()
            ->toHaveLength(64);
    });
});

describe('SM3 Edge Cases', function () {

    test('handles binary data', function () {
        $sm3 = new SM3();
        $binaryData = "\x00\x01\x02\x03\x04\x05";
        $hash = $sm3->hash($binaryData);

        expect($hash)
            ->toBeString()
            ->toHaveLength(64);
    });

    test('handles unicode characters', function () {
        $sm3 = new SM3();
        $unicode = '🔐🔑🛡️';
        $hash = $sm3->hash($unicode);

        expect($hash)
            ->toBeString()
            ->toHaveLength(64);
    });

    test('handles newlines and special chars', function () {
        $sm3 = new SM3();
        $special = "line1\nline2\ttab\rcarriage";
        $hash = $sm3->hash($special);

        expect($hash)
            ->toBeString()
            ->toHaveLength(64);
    });
});

describe('official vector tests ', function () {
    test('sm3 raw encryption matches standard test vector', function () {
        $sm3 = new SM3();

        $plaintext = 'abc';
        $ciphertext = '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0';
        $encrypted = $sm3->hash($plaintext);

        $plaintext1 = '中国';
        $ciphertext1 = '0703890aa604c0975c7e85c664c974cc02532ac79d374d4c2a8617d6f8c04d7a';
        $encrypted1 = $sm3->hash($plaintext1);

        expect($encrypted)->toBe($ciphertext)
            ->and($encrypted1)->toBe($ciphertext1);
    });
});