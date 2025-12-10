# laravel-gm-crypto  国密算法扩展包

Laravel 国密算法（SM3/SM4）扩展包，支持 SM3 哈希算法和 SM4 对称加密算法。

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.2-blue.svg)](https://php.net)
[![Laravel Version](https://img.shields.io/badge/laravel-%3E%3D12.0-red.svg)](https://laravel.com)

## 特性

- ✅ **SM3 哈希算法**：支持标准 SM3 和 HMAC-SM3
- ✅ **SM4 对称加密**：支持 ECB、CBC 等多种模式
- ✅ **灵活配置**：支持通过配置文件或环境变量配置
- ✅ **多种编码**：支持 Base64、十六进制等多种输出格式
- ✅ **Facade 支持**：提供便捷的 Facade 调用方式
- ✅ **依赖注入**：支持 Laravel 依赖注入
- ✅ **驱动管理**：采用 Laravel Manager 模式，易于扩展

## 安装

通过 Composer 安装：

```bash
composer require xgrug/laravel-gm-crypto
```

发布配置文件（可选）：

```bash
php artisan vendor:publish --tag=gmcrypto-config
```

## 配置

### 环境变量配置

在 `.env` 文件中添加配置：

```env
# 默认驱动
GM_CRYPTO_DRIVER=sm4

# SM4 配置
GM_SM4_KEY=0123456789abcdeffedcba9876543210
GM_SM4_MODE=CBC
GM_SM4_IV=fedcba98765432100123456789abcdef
GM_SM4_PADDING=none

# SM3 配置
GM_SM3_HMAC=false
GM_SM3_HMAC_KEY=
```

### 配置文件

配置文件位于 `config/gmcrypto.php`：

```php
return [
    'default' => env('GM_CRYPTO_DRIVER', 'sm4'),
    
    'sm4' => [
        'key' => env('GM_SM4_KEY', '0123456789abcdeffedcba9876543210'),
        'mode' => env('GM_SM4_MODE', 'CBC'),
        'iv' => env('GM_SM4_IV', 'fedcba98765432100123456789abcdef'),
        'padding' => env('GM_SM4_PADDING', 'pkcs7'),
    ],
    
    'sm3' => [
        'hmac' => env('GM_SM3_HMAC', false),
        'hmac_key' => env('GM_SM3_HMAC_KEY', ''),
    ],
];
```

## 使用方法

### SM3 哈希算法

```php
use Xgrug\LaravelGmCrypto\Facades\GmCrypto;

// 计算 SM3 哈希
$hash = GmCrypto::sm3Hash('Hello World');
// 输出: 44f0061e69fa6fdfc290c494654a05dc0c053da7e5c52b84ef93a9d67d3fff88

// 验证哈希
$isValid = GmCrypto::sm3Verify('Hello World', $hash);
// 返回: true

// HMAC-SM3
$hmac = GmCrypto::sm3Hmac('Hello World', 'secret-key');
```

### SM4 对称加密

```php
use Xgrug\LaravelGmCrypto\Facades\GmCrypto;

$plaintext = '敏感数据';

// 加密（返回 Base64）
$encrypted = GmCrypto::sm4Encrypt($plaintext);

// 解密
$decrypted = GmCrypto::sm4Decrypt($encrypted);

// 十六进制格式
$encryptedHex = GmCrypto::sm4EncryptHex($plaintext);
$decryptedHex = GmCrypto::sm4DecryptHex($encryptedHex);
```

### 在控制器中使用

```php
use Xgrug\LaravelGmCrypto\GmCryptoManager;

class UserController extends Controller
{
    public function __construct(
        private GmCryptoManager $crypto
    ) {}

    public function store(Request $request)
    {
        $encryptedData = $this->crypto->sm4Encrypt($request->sensitive_data);
        
        User::create([
            'data' => $encryptedData
        ]);
    }
}
```

### 在 Model 中自动加密

```php
use Illuminate\Database\Eloquent\Model;
use Xgrug\LaravelGmCrypto\Facades\GmCrypto;

class User extends Model
{
    // 自动加密
    public function setPhoneAttribute($value)
    {
        $this->attributes['phone'] = GmCrypto::sm4Encrypt($value);
    }

    // 自动解密
    public function getPhoneAttribute($value)
    {
        return GmCrypto::sm4Decrypt($value);
    }
}
```

### 直接使用驱动

```php
// 使用 SM3 驱动
$sm3 = GmCrypto::driver('sm3');
$hash = $sm3->hash('数据');

// 使用 SM4 驱动
$sm4 = GmCrypto::driver('sm4');
$encrypted = $sm4->encrypt('明文');
```

### 自定义配置

```php
use Xgrug\LaravelGmCrypto\SM4;

$sm4 = new SM4([
    'key' => '自定义密钥',
    'mode' => 'ECB',
    'padding' => 'pkcs7'
]);

$encrypted = $sm4->encryptBase64('明文');
```

## API 文档

### SM3 类

#### 方法

- `hash(string $message): string` - 计算 SM3 哈希
- `hmac(string $message, string $key): string` - 计算 HMAC-SM3
- `verify(string $message, string $hash): bool` - 验证哈希值

### SM4 类

#### 方法

- `encrypt(string $plaintext): string` - 加密（返回二进制）
- `decrypt(string $ciphertext): string` - 解密
- `encryptBase64(string $plaintext): string` - 加密并返回 Base64
- `decryptBase64(string $ciphertext): string` - 解密 Base64 字符串
- `encryptHex(string $plaintext): string` - 加密并返回十六进制
- `decryptHex(string $ciphertext): string` - 解密十六进制字符串

#### 支持的加密模式

- `ECB` - 电子密码本模式
- `CBC` - 密码块链接模式（推荐）

#### 支持的填充方式

- `pkcs7` - PKCS#7 填充（推荐）
- `zero` - 零填充

## 实际应用场景

### 1. 敏感数据加密存储

```php
// 加密用户身份证号、手机号等敏感信息
$user->id_card = GmCrypto::sm4Encrypt($request->id_card);
$user->phone = GmCrypto::sm4Encrypt($request->phone);
```

### 2. 数据完整性校验

```php
// 生成数据签名
$data = ['user_id' => 123, 'amount' => 1000];
$signature = GmCrypto::sm3Hash(json_encode($data));

// 验证签名
if (GmCrypto::sm3Verify(json_encode($data), $signature)) {
    // 数据未被篡改
}
```

### 3. API 接口签名

```php
// 中间件验证请求签名
public function handle(Request $request, Closure $next)
{
    $signature = $request->header('X-Signature');
    $payload = $request->getContent();
    
    if (!GmCrypto::sm3Verify($payload, $signature)) {
        return response()->json(['error' => '签名验证失败'], 403);
    }
    
    return $next($request);
}
```

## 安全建议

1. **密钥管理**：不要在代码中硬编码密钥，使用环境变量存储
2. **定期更换密钥**：建议定期更换加密密钥
3. **使用 CBC 模式**：相比 ECB 模式更安全
4. **HTTPS 传输**：加密数据在传输时仍需使用 HTTPS
5. **密钥长度**：SM4 密钥必须为 128 位（32 位十六进制字符）

## 依赖要求

- PHP >= 8.2
- Laravel >= 10
- OpenSSL 扩展

## 性能优化

- SM3/SM4 算法采用纯 PHP 实现，性能略低于原生扩展
- 建议在高并发场景下使用缓存减少重复计算
- 考虑使用 C 扩展（如 OpenSSL）以获得更好性能

## 测试

```bash
composer test
```

## 贡献

欢迎提交 Pull Request 或报告问题。

## 许可证

MIT License

## 相关资源

- [国密算法标准文档](http://www.gmbz.org.cn/)

## 更新日志

### v1.0.0 (2024-12-10)

- 初始版本发布
- 支持 SM3 哈希算法
- 支持 SM4 对称加密算法
- 支持 ECB、CBC 模式
- 提供 Facade 和依赖注入支持