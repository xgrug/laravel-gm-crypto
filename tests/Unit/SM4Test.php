<?php

use Xgrug\LaravelGmCrypto\SM4;

describe('SM4 Encryption/Decryption', function () {

    test('can encrypt and decrypt simple text', function () {
        $sm4 = new SM4();
        $plaintext = 'Hello World';

        $encrypted = $sm4->encrypt($plaintext);
        $decrypted = $sm4->decrypt($encrypted);

        expect($decrypted)->toBe($plaintext);
    });

    test('can encrypt and decrypt empty string', function () {
        $sm4 = new SM4();
        $plaintext = '';

        $encrypted = $sm4->encrypt($plaintext);
        $decrypted = $sm4->decrypt($encrypted);

        expect($decrypted)->toBe($plaintext);
    });

    test('can encrypt and decrypt chinese characters', function () {
        $sm4 = new SM4();
        $plaintext = '你好世界，这是测试数据';

        $encrypted = $sm4->encrypt($plaintext);
        $decrypted = $sm4->decrypt($encrypted);

        expect($decrypted)->toBe($plaintext);
    });

    test('can encrypt and decrypt long text', function () {
        $sm4 = new SM4();
        $plaintext = str_repeat('这是一段很长的测试数据。', 100);

        $encrypted = $sm4->encrypt($plaintext);
        $decrypted = $sm4->decrypt($encrypted);

        expect($decrypted)->toBe($plaintext);
    });

    test('encrypted data is different from plaintext', function () {
        $sm4 = new SM4();
        $plaintext = 'secret message';

        $encrypted = $sm4->encrypt($plaintext);

        expect($encrypted)->not->toBe($plaintext);
    });

    test('same plaintext with same key produces same ciphertext in ECB mode', function () {
        $sm4 = new SM4([
            'mode' => 'ECB',
            'key' => '0123456789abcdeffedcba9876543210'
        ]);
        $plaintext = 'hello word';

        $encrypted1 = $sm4->encrypt($plaintext);
        $encrypted2 = $sm4->encrypt($plaintext);
        expect($encrypted1)->toBe($encrypted2);
    });

    test('encrypts special characters correctly', function () {
        $sm4 = new SM4();
        $plaintext = "Special: !@#$%^&*()_+-=[]{}|;':\",./<>?";

        $encrypted = $sm4->encrypt($plaintext);
        $decrypted = $sm4->decrypt($encrypted);

        expect($decrypted)->toBe($plaintext);
    });

    test('encrypts unicode emojis correctly', function () {
        $sm4 = new SM4();
        $plaintext = '测试表情符号：😀🎉🔐🛡️';

        $encrypted = $sm4->encrypt($plaintext);
        $decrypted = $sm4->decrypt($encrypted);

        expect($decrypted)->toBe($plaintext);
    });
});

describe('SM4 Base64 Encoding', function () {

    test('can encrypt to base64 and decrypt', function () {
        $sm4 = new SM4();
        $plaintext = 'Base64 Test';

        $encrypted = $sm4->encryptBase64($plaintext);
        $decrypted = $sm4->decryptBase64($encrypted);

        expect($encrypted)->toMatch('/^[A-Za-z0-9+\/=]+$/')
            ->and($decrypted)->toBe($plaintext);
    });

    test('base64 output is valid', function () {
        $sm4 = new SM4();
        $encrypted = $sm4->encryptBase64('test');

        expect(base64_decode($encrypted, true))->not->toBeFalse();
    });

    test('can handle long text with base64', function () {
        $sm4 = new SM4();
        $plaintext = str_repeat('Long text for base64 encoding test. ', 50);

        $encrypted = $sm4->encryptBase64($plaintext);
        $decrypted = $sm4->decryptBase64($encrypted);

        expect($decrypted)->toBe($plaintext);
    });
});

describe('SM4 Hexadecimal Encoding', function () {

    test('can encrypt to hex and decrypt', function () {
        $sm4 = new SM4();
        $plaintext = 'Hex Test';

        $encrypted = $sm4->encryptHex($plaintext);
        $decrypted = $sm4->decryptHex($encrypted);

        expect($encrypted)->toMatch('/^[0-9a-f]+$/')
            ->and($decrypted)->toBe($plaintext);
    });

    test('hex output length is even', function () {
        $sm4 = new SM4();
        $encrypted = $sm4->encryptHex('test');

        expect(strlen($encrypted) % 2)->toBe(0);
    });

    test('can handle chinese text with hex', function () {
        $sm4 = new SM4();
        $plaintext = '十六进制编码测试';

        $encrypted = $sm4->encryptHex($plaintext);
        $decrypted = $sm4->decryptHex($encrypted);

        expect($decrypted)->toBe($plaintext);
    });
});

describe('SM4 CBC Mode', function () {

    test('CBC mode encrypts and decrypts correctly', function () {
        $sm4 = new SM4([
            'mode' => 'CBC',
            'key' => '0123456789abcdeffedcba9876543210',
            'iv' => 'fedcba98765432100123456789abcdef'
        ]);
        $plaintext = 'CBC Mode Test';

        $encrypted = $sm4->encrypt($plaintext);
        $decrypted = $sm4->decrypt($encrypted);

        expect($decrypted)->toBe($plaintext);
    });

    test('CBC mode with different IV produces different ciphertext', function () {
        $plaintext = 'test';

        $sm4_1 = new SM4([
            'mode' => 'CBC',
            'key' => '0123456789abcdeffedcba9876543210',
            'iv' => '00000000000000000000000000000000'
        ]);

        $sm4_2 = new SM4([
            'mode' => 'CBC',
            'key' => '0123456789abcdeffedcba9876543210',
            'iv' => '11111111111111111111111111111111'
        ]);

        $encrypted1 = $sm4_1->encrypt($plaintext);
        $encrypted2 = $sm4_2->encrypt($plaintext);

        expect($encrypted1)->not->toBe($encrypted2);
    });

});

describe('SM4 ECB Mode', function () {

    test('ECB mode encrypts and decrypts correctly', function () {
        $sm4 = new SM4([
            'mode' => 'ECB',
            'key' => '0123456789abcdeffedcba9876543210'
        ]);
        $plaintext = 'ECB Mode Test';

        $encrypted = $sm4->encrypt($plaintext);
        $decrypted = $sm4->decrypt($encrypted);

        expect($decrypted)->toBe($plaintext);
    });

    test('ECB mode produces deterministic output', function () {
        $sm4 = new SM4(['mode' => 'ECB']);
        $plaintext = 'deterministic';

        $encrypted1 = $sm4->encrypt($plaintext);
        $encrypted2 = $sm4->encrypt($plaintext);

        expect($encrypted1)->toBe($encrypted2);
    });
});

describe('SM4 Padding', function () {

    test('PKCS7 padding works correctly', function () {
        $sm4 = new SM4(['padding' => 'pkcs7']);
        $plaintext = 'test';

        $encrypted = $sm4->encrypt($plaintext);
        $decrypted = $sm4->decrypt($encrypted);

        expect($decrypted)->toBe($plaintext);
    });

    test('zero padding works correctly', function () {
        $sm4 = new SM4(['padding' => 'zero']);
        $plaintext = 'test';

        $encrypted = $sm4->encrypt($plaintext);
        $decrypted = $sm4->decrypt($encrypted);

        expect($decrypted)->toBe($plaintext);
    });

    test('handles exact block size with PKCS7', function () {
        $sm4 = new SM4(['padding' => 'pkcs7']);
        $plaintext = str_repeat('a', 16); // Exact block size

        $encrypted = $sm4->encrypt($plaintext);
        $decrypted = $sm4->decrypt($encrypted);

        expect($decrypted)->toBe($plaintext);
    });
});

describe('SM4 Different Keys', function () {

    test('different keys produce different ciphertexts', function () {
        $plaintext = 'same message';

        $sm4_1 = new SM4(['key' => '0123456789abcdeffedcba9876543210']);
        $sm4_2 = new SM4(['key' => 'fedcba98765432100123456789abcdef']);

        $encrypted1 = $sm4_1->encrypt($plaintext);
        $encrypted2 = $sm4_2->encrypt($plaintext);

        expect($encrypted1)->not->toBe($encrypted2);
    });

    test('wrong key fails to decrypt', function () {
        $plaintext = 'secret';

        $sm4_encrypt = new SM4(['key' => '0123456789abcdeffedcba9876543210']);
        $sm4_decrypt = new SM4(['key' => 'fedcba98765432100123456789abcdef']);

        $encrypted = $sm4_encrypt->encrypt($plaintext);
        $decrypted = $sm4_decrypt->decrypt($encrypted);

        expect($decrypted)->not->toBe($plaintext);
    });

    test('correct key successfully decrypts', function () {
        $plaintext = 'secret message';
        $key = '0123456789abcdeffedcba9876543210';

        $sm4_1 = new SM4(['key' => $key]);
        $sm4_2 = new SM4(['key' => $key]);

        $encrypted = $sm4_1->encrypt($plaintext);
        $decrypted = $sm4_2->decrypt($encrypted);

        expect($decrypted)->toBe($plaintext);
    });
});

describe('SM4 Edge Cases', function () {

    test('handles exactly 16 bytes', function () {
        $sm4 = new SM4();
        $plaintext = '1234567890123456'; // Exactly 16 bytes

        $encrypted = $sm4->encrypt($plaintext);
        $decrypted = $sm4->decrypt($encrypted);

        expect($decrypted)->toBe($plaintext);
    });

    test('handles exactly 32 bytes', function () {
        $sm4 = new SM4();
        $plaintext = '12345678901234561234567890123456'; // Exactly 32 bytes

        $encrypted = $sm4->encrypt($plaintext);
        $decrypted = $sm4->decrypt($encrypted);

        expect($decrypted)->toBe($plaintext);
    });

    test('handles single character', function () {
        $sm4 = new SM4();
        $plaintext = 'a';

        $encrypted = $sm4->encrypt($plaintext);
        $decrypted = $sm4->decrypt($encrypted);

        expect($decrypted)->toBe($plaintext);
    });

    test('handles binary data', function () {
        $sm4 = new SM4();
        $plaintext = "\x00\x01\x02\x03\x04\x05\x06\x07";

        $encrypted = $sm4->encrypt($plaintext);
        $decrypted = $sm4->decrypt($encrypted);

        expect($decrypted)->toBe($plaintext);
    });

    test('handles newlines and whitespace', function () {
        $sm4 = new SM4();
        $plaintext = "line1\nline2\ttab\rcarriage   spaces";

        $encrypted = $sm4->encrypt($plaintext);
        $decrypted = $sm4->decrypt($encrypted);

        expect($decrypted)->toBe($plaintext);
    });
});
describe('official vector tests ', function () {
//官方 标准 SM4 测试
    test('sm4 raw encryption matches standard test vector', function () {
        $sm4 = new SM4([
            'key' => ('0123456789abcdeffedcba9876543210'),
            'mode' => 'ECB',
            'padding' => 'none'
        ]);

        $plaintext = hex2bin('0123456789abcdeffedcba9876543210');
        $encrypted = $sm4->encryptHex($plaintext, false); // 不自动填充
        $ciphertext = bin2hex($encrypted);

        expect($ciphertext)->toBe('681edf34d206965e86b3e94f536e4246');
    });

    test('sm4 encrypt and decrypt with pkcs7 padding', function () {
        $sm4 = new SM4([
            'key' => '0123456789abcdeffedcba9876543210',
            'mode' => 'ECB',
            'padding' => 'pkcs7'
        ]);

        // 16字节的数据，PKCS7 会添加 16 字节填充
        $plaintext = hex2bin('0123456789abcdeffedcba9876543210');

        $encrypted = $sm4->encrypt($plaintext); // 自动填充
        $decrypted = $sm4->decrypt($encrypted); // 自动去填充

        // 解密后应该恢复原始数据
        expect($decrypted)->toBe($plaintext);

        // 密文长度应该是 32 字节（16 + 16 填充）
        expect(strlen($encrypted))->toBe(32);
    });

    test('sm4 encrypts non-block-aligned data correctly', function () {
        $sm4 = new SM4([
            'key' => '0123456789abcdeffedcba9876543210',
            'mode' => 'ECB',
            'padding' => 'pkcs7'
        ]);

        $plaintext = 'Hello World'; // 11 字节，会填充 5 字节

        $encrypted = $sm4->encrypt($plaintext);
        $decrypted = $sm4->decrypt($encrypted);

        expect($decrypted)->toBe($plaintext);
    });

    test('sm4 matches multiple standard test vectors', function () {
        $testVectors = [
            [
                'key' => '0123456789abcdeffedcba9876543210',
                'plain' => '0123456789abcdeffedcba9876543210',
                'cipher' => '681edf34d206965e86b3e94f536e4246'
            ],
            [
                'key' => 'fedcba98765432100123456789abcdef',
                'plain' => 'fedcba98765432100123456789abcdef',
                'cipher' => 'fcad24d11be5ed6f508568719eab1462'
            ],
        ];

        foreach ($testVectors as $vector) {
            $sm4 = new SM4([
                'key' => $vector['key'],
                'mode' => 'ECB',
                'padding' => 'none'
            ]);

            $plaintext = hex2bin($vector['plain']);
            $encrypted = $sm4->encrypt($plaintext, false);
            $ciphertext = bin2hex($encrypted);

            expect($ciphertext)->toBe($vector['cipher']);
        }
    });

    test('sm4 cbc mode with standard test vector', function () {
        $sm4 = new SM4([
            'key' => 'EEF3C9888129755F2C769DBC459448CE',
            'mode' => 'CBC',
            'iv' => 'FBD7B7AB0793F814B28A970F9E859C05',
            'padding' => 'none'
        ]);

        $plaintext = hex2bin('99c9d02d03f2cd394a680dc51b112322');
        $encrypted = $sm4->encrypt($plaintext, false);
        $decrypted = $sm4->decrypt($encrypted, false);
        expect(bin2hex($decrypted))->toBe('99c9d02d03f2cd394a680dc51b112322');
    });
});