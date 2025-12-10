<?php

namespace Xgrug\LaravelGmCrypto;

class SM3
{
    private const IV = [
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    ];

    private array $config;

    public function __construct(array $config = [])
    {
        $this->config = $config;
    }

    /**
     * SM3哈希计算
     */
    public function hash(string $message): string
    {
        if (!empty($this->config['hmac']) && !empty($this->config['hmac_key'])) {
            return $this->hmac($message, $this->config['hmac_key']);
        }

        return $this->calculateHash($message);
    }

    /**
     * HMAC-SM3
     */
    public function hmac(string $message, string $key): string
    {
        $blockSize = 64;

        if (strlen($key) > $blockSize) {
            $key = hex2bin($this->calculateHash($key));
        }

        $key = str_pad($key, $blockSize, "\0");

        $ipad = str_repeat("\x36", $blockSize);
        $opad = str_repeat("\x5c", $blockSize);

        $ipadKey = $key ^ $ipad;
        $opadKey = $key ^ $opad;

        $innerHash = $this->calculateHash($ipadKey . $message);

        return $this->calculateHash($opadKey . hex2bin($innerHash));
    }

    /**
     * 计算原始 SM3 哈希（内部方法，避免递归）
     */
    private function calculateHash(string $message): string
    {
        $msg = $this->prepareMessage($message);
        $v = self::IV;

        for ($i = 0; $i < count($msg) / 16; $i++) {
            $b = array_slice($msg, $i * 16, 16);
            $v = $this->cf($v, $b);
        }

        return $this->toHex($v);
    }

    /**
     * 验证哈希
     */
    public function verify(string $message, string $hash): bool
    {
        return hash_equals($this->hash($message), strtolower($hash));
    }

    private function prepareMessage(string $message): array
    {
        // Convert message to byte array
        if ($message === '') {
            $bits = [];
        } else {
            $bits = array_values(unpack('C*', $message));
        }

        $msgLen = count($bits);
        $bitLen = $msgLen * 8;

        // Append 0x80
        $bits[] = 0x80;

        // Pad with zeros until length ≡ 448 (mod 512)
        while ((count($bits) * 8) % 512 !== 448) {
            $bits[] = 0x00;
        }

        // Append message length as 64-bit big-endian
        for ($i = 7; $i >= 0; $i--) {
            $bits[] = ($bitLen >> ($i * 8)) & 0xff;
        }

        // Convert bytes to 32-bit words
        $words = [];
        $numWords = count($bits) / 4;
        for ($i = 0; $i < $numWords; $i++) {
            $idx = $i * 4;
            $words[] = ($bits[$idx] << 24) | ($bits[$idx + 1] << 16) |
                ($bits[$idx + 2] << 8) | $bits[$idx + 3];
        }

        return $words;
    }

    private function cf(array $v, array $b): array
    {
        $w = $this->expand($b);
        $a = $v[0]; $b = $v[1]; $c = $v[2]; $d = $v[3];
        $e = $v[4]; $f = $v[5]; $g = $v[6]; $h = $v[7];

        for ($j = 0; $j < 64; $j++) {
            $ss1 = $this->rotl($this->add($this->add($this->rotl($a, 12), $e), $this->rotl($this->t($j), $j % 32)), 7);
            $ss2 = $ss1 ^ $this->rotl($a, 12);
            $tt1 = $this->add($this->add($this->add($this->ff($a, $b, $c, $j), $d), $ss2), $w[$j + 68]);
            $tt2 = $this->add($this->add($this->add($this->gg($e, $f, $g, $j), $h), $ss1), $w[$j]);

            $d = $c;
            $c = $this->rotl($b, 9);
            $b = $a;
            $a = $tt1;
            $h = $g;
            $g = $this->rotl($f, 19);
            $f = $e;
            $e = $this->p0($tt2);
        }

        return [
            $a ^ $v[0], $b ^ $v[1], $c ^ $v[2], $d ^ $v[3],
            $e ^ $v[4], $f ^ $v[5], $g ^ $v[6], $h ^ $v[7]
        ];
    }

    private function expand(array $b): array
    {
        $w = $b;

        for ($j = 16; $j < 68; $j++) {
            $w[$j] = $this->p1($w[$j - 16] ^ $w[$j - 9] ^ $this->rotl($w[$j - 3], 15)) ^
                $this->rotl($w[$j - 13], 7) ^ $w[$j - 6];
        }

        for ($j = 0; $j < 64; $j++) {
            $w[$j + 68] = $w[$j] ^ $w[$j + 4];
        }

        return $w;
    }

    private function ff(int $x, int $y, int $z, int $j): int
    {
        return $j < 16 ? ($x ^ $y ^ $z) : (($x & $y) | ($x & $z) | ($y & $z));
    }

    private function gg(int $x, int $y, int $z, int $j): int
    {
        return $j < 16 ? ($x ^ $y ^ $z) : (($x & $y) | (~$x & $z));
    }

    private function t(int $j): int
    {
        return $j < 16 ? 0x79cc4519 : 0x7a879d8a;
    }

    private function p0(int $x): int
    {
        return $x ^ $this->rotl($x, 9) ^ $this->rotl($x, 17);
    }

    private function p1(int $x): int
    {
        return $x ^ $this->rotl($x, 15) ^ $this->rotl($x, 23);
    }

    private function rotl(int $x, int $n): int
    {
        $n = $n % 32;
        return (($x << $n) | ($x >> (32 - $n))) & 0xffffffff;
    }

    private function add(...$nums): int
    {
        $sum = 0;
        foreach ($nums as $num) {
            $sum = ($sum + $num) & 0xffffffff;
        }
        return $sum;
    }

    private function toHex(array $words): string
    {
        $hex = '';
        foreach ($words as $word) {
            $hex .= sprintf('%08x', $word);
        }
        return $hex;
    }
}