<?php

namespace Xgrug\LaravelGmCrypto;

use Illuminate\Support\Manager;

class GmCryptoManager extends Manager
{
    /**
     * 获取默认驱动名称
     */
    public function getDefaultDriver(): string
    {
        return $this->config->get('gmcrypto.default', 'sm4');
    }

    /**
     * 创建 SM3 驱动实例
     */
    protected function createSm3Driver(): SM3
    {
        return new SM3($this->config->get('gmcrypto.sm3', []));
    }

    /**
     * 创建 SM4 驱动实例
     */
    protected function createSm4Driver(): SM4
    {
        return new SM4($this->config->get('gmcrypto.sm4', []));
    }

    /**
     * 快捷方法：SM3 哈希
     */
    public function sm3Hash(string $message): string
    {
        return $this->driver('sm3')->hash($message);
    }

    /**
     * 快捷方法：SM3 HMAC
     */
    public function sm3Hmac(string $message, string $key): string
    {
        return $this->driver('sm3')->hmac($message, $key);
    }

    /**
     * 快捷方法：SM3 验证
     */
    public function sm3Verify(string $message, string $hash): bool
    {
        return $this->driver('sm3')->verify($message, $hash);
    }

    /**
     * 快捷方法：SM4 加密
     */
    public function sm4Encrypt(string $plaintext): string
    {
        return $this->driver('sm4')->encryptBase64($plaintext);
    }

    /**
     * 快捷方法：SM4 解密
     */
    public function sm4Decrypt(string $ciphertext): string
    {
        return $this->driver('sm4')->decryptBase64($ciphertext);
    }

    /**
     * 快捷方法：SM4 加密（十六进制）
     */
    public function sm4EncryptHex(string $plaintext): string
    {
        return $this->driver('sm4')->encryptHex($plaintext);
    }

    /**
     * 快捷方法：SM4 解密（十六进制）
     */
    public function sm4DecryptHex(string $ciphertext): string
    {
        return $this->driver('sm4')->decryptHex($ciphertext);
    }
}