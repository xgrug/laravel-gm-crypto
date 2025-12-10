<?php

use Xgrug\LaravelGmCrypto\Facades\GmCrypto;

describe('Real World Scenarios', function () {

    test('can encrypt and store sensitive user data', function () {
        $userData = [
            'name' => '张三',
            'id_card' => '110101199001011234',
            'phone' => '13800138000',
            'email' => 'zhangsan@example.com'
        ];

        // Encrypt sensitive fields
        $encryptedIdCard = GmCrypto::sm4Encrypt($userData['id_card']);
        $encryptedPhone = GmCrypto::sm4Encrypt($userData['phone']);

        // Store encrypted data
        $stored = [
            'name' => $userData['name'],
            'id_card' => $encryptedIdCard,
            'phone' => $encryptedPhone,
            'email' => $userData['email']
        ];

        // Later, decrypt when needed
        $decryptedIdCard = GmCrypto::sm4Decrypt($stored['id_card']);
        $decryptedPhone = GmCrypto::sm4Decrypt($stored['phone']);

        expect($decryptedIdCard)->toBe($userData['id_card'])
            ->and($decryptedPhone)->toBe($userData['phone']);
    });

    test('can create and verify data signature', function () {
        $transaction = [
            'user_id' => 12345,
            'action' => 'transfer',
            'amount' => 1000.00,
            'timestamp' => time()
        ];

        $data = json_encode($transaction);

        // Create signature
        $signature = GmCrypto::sm3Hash($data);

        // Later, verify signature
        $isValid = GmCrypto::sm3Verify($data, $signature);

        expect($isValid)->toBeTrue();

        // Tampered data should fail verification
        $tamperedData = json_encode(array_merge($transaction, ['amount' => 10000.00]));
        $isTampered = GmCrypto::sm3Verify($tamperedData, $signature);

        expect($isTampered)->toBeFalse();
    });

    test('can implement HMAC-based API authentication', function () {
        $apiKey = 'my-secret-api-key';
        $requestData = [
            'endpoint' => '/api/users',
            'method' => 'POST',
            'timestamp' => time(),
            'body' => ['name' => 'Test User']
        ];

        $payload = json_encode($requestData);

        // Client generates HMAC signature
        $clientSignature = GmCrypto::sm3Hmac($payload, $apiKey);

        // Server verifies signature
        $serverSignature = GmCrypto::sm3Hmac($payload, $apiKey);

        expect($clientSignature)->toBe($serverSignature);
    });

    test('can encrypt configuration files', function () {
        $config = [
            'database' => [
                'host' => 'localhost',
                'username' => 'root',
                'password' => 'super-secret-password',
                'database' => 'myapp'
            ],
            'api_keys' => [
                'wechat' => 'wx1234567890abcdef',
                'alipay' => 'alipay_secret_key'
            ]
        ];

        $serialized = serialize($config);

        // Encrypt entire config
        $encrypted = GmCrypto::sm4Encrypt($serialized);

        // Store encrypted config...

        // Later, decrypt and restore
        $decrypted = GmCrypto::sm4Decrypt($encrypted);
        $restored = unserialize($decrypted);

        expect($restored)->toBe($config);
    });

    test('can implement secure token generation', function () {
        $userId = 12345;
        $expiry = time() + 3600;

        $tokenData = json_encode([
            'user_id' => $userId,
            'expiry' => $expiry,
            'random' => bin2hex(random_bytes(16))
        ]);

        // Encrypt token data
        $token = GmCrypto::sm4EncryptHex($tokenData);

        // Later, validate token
        $decryptedData = GmCrypto::sm4DecryptHex($token);
        $parsed = json_decode($decryptedData, true);

        expect($parsed['user_id'])->toBe($userId)
            ->and($parsed['expiry'])->toBeGreaterThan(time());
    });
});

describe('Performance Tests', function () {

    test('can handle batch encryption efficiently', function () {
        $items = [];
        for ($i = 0; $i < 100; $i++) {
            $items[] = "Item {$i}: " . str_repeat('data', 10);
        }

        $encrypted = [];
        foreach ($items as $item) {
            $encrypted[] = GmCrypto::sm4Encrypt($item);
        }

        $decrypted = [];
        foreach ($encrypted as $enc) {
            $decrypted[] = GmCrypto::sm4Decrypt($enc);
        }

        expect($decrypted)->toBe($items);
    });

    test('can handle large data encryption', function () {
        $largeData = str_repeat('Lorem ipsum dolor sit amet. ', 1000);

        $encrypted = GmCrypto::sm4Encrypt($largeData);
        $decrypted = GmCrypto::sm4Decrypt($encrypted);

        expect($decrypted)->toBe($largeData);
    });

    test('sm3 hash performance with multiple calls', function () {
        $hashes = [];

        for ($i = 0; $i < 100; $i++) {
            $hashes[] = GmCrypto::sm3Hash("message_{$i}");
        }

        expect($hashes)->toHaveCount(100)
            ->and($hashes[0])->not->toBe($hashes[1]);
    });
});

describe('Error Handling', function () {

    test('handles invalid hex gracefully', function () {
        expect(fn() => GmCrypto::sm4DecryptHex('invalid-hex-zzz'))
            ->toThrow(Exception::class);
    });

    test('handles empty encryption', function () {
        $encrypted = GmCrypto::sm4Encrypt('');
        $decrypted = GmCrypto::sm4Decrypt($encrypted);

        expect($decrypted)->toBe('');
    });
});

describe('Compatibility Tests', function () {

    test('sm3 hash output format is consistent', function () {
        $hash = GmCrypto::sm3Hash('test');

        expect($hash)
            ->toBeString()
            ->toHaveLength(64)
            ->toMatch('/^[0-9a-f]{64}$/');
    });

    test('sm4 base64 output is url-safe decodable', function () {
        $plaintext = 'url safe test';
        $encrypted = GmCrypto::sm4Encrypt($plaintext);

        // Should be valid base64
        $decoded = base64_decode($encrypted, true);

        expect($decoded)->not->toBeFalse();
    });

    test('can handle different character encodings', function () {
        $texts = [
            'ASCII: Hello World',
            'UTF-8: 你好世界',
            'Emoji: 😀🎉🔐',
            'Mixed: Hello 世界 🌍',
            'Special: <>&"\'`'
        ];

        foreach ($texts as $text) {
            $encrypted = GmCrypto::sm4Encrypt($text);
            $decrypted = GmCrypto::sm4Decrypt($encrypted);

            expect($decrypted)->toBe($text);
        }
    });
});