# Laravel CA PKCS#12

> Pure PHP PKCS#12 (PFX) bundle management for Laravel, implementing RFC 7292 with modern and legacy encryption support.

[![Latest Version on Packagist](https://img.shields.io/packagist/v/groupesti/laravel-ca-pkcs12.svg)](https://packagist.org/packages/groupesti/laravel-ca-pkcs12)
[![PHP Version](https://img.shields.io/badge/php-8.4%2B-blue)](https://www.php.net/releases/8.4/)
[![Laravel](https://img.shields.io/badge/laravel-12.x%20|%2013.x-red)](https://laravel.com)
[![Tests](https://github.com/groupesti/laravel-ca-pkcs12/actions/workflows/tests.yml/badge.svg)](https://github.com/groupesti/laravel-ca-pkcs12/actions/workflows/tests.yml)
[![License](https://img.shields.io/github/license/groupesti/laravel-ca-pkcs12)](LICENSE.md)

## Requirements

- PHP 8.4+
- Laravel 12.x or 13.x
- `groupesti/laravel-ca` ^0.1
- `groupesti/laravel-ca-crt` ^0.1
- `groupesti/laravel-ca-key` ^0.1
- `groupesti/laravel-ca-log` ^0.1
- `phpseclib/phpseclib` ^3.0
- PHP extensions: `mbstring`, `openssl`

## Installation

```bash
composer require groupesti/laravel-ca-pkcs12
```

Publish the configuration file:

```bash
php artisan vendor:publish --tag=ca-pkcs12-config
```

Publish and run the migrations:

```bash
php artisan vendor:publish --tag=ca-pkcs12-migrations
php artisan migrate
```

## Configuration

The configuration file `config/ca-pkcs12.php` exposes the following options:

| Key | Type | Default | Description |
|---|---|---|---|
| `default_encryption` | `string` | `'aes-256-cbc'` | Symmetric encryption algorithm for PKCS#12 contents. Supported: `aes-256-cbc`, `aes-128-cbc`, `3des-cbc`. |
| `default_mac` | `string` | `'sha256'` | Hash algorithm for the PKCS#12 integrity MAC. Supported: `sha256`, `sha384`, `sha512`, `sha1`. |
| `mac_iterations` | `int` | `2048` | Number of iterations for MAC key derivation. |
| `kdf_iterations` | `int` | `2048` | Number of iterations for password-based key derivation (encryption). |
| `include_chain` | `bool` | `true` | Whether to include the full certificate chain in PKCS#12 bundles by default. |
| `legacy_compatibility` | `bool` | `false` | When `true`, uses PBE-SHA1-3DES and SHA-1 MAC for compatibility with legacy systems (Windows XP, older Java). |
| `routes.enabled` | `bool` | `true` | Enable or disable the package API routes. |
| `routes.prefix` | `string` | `'api/ca/pkcs12'` | URL prefix for API routes. |
| `routes.middleware` | `array` | `['api']` | Middleware applied to API routes. |

## Usage

### Creating a PKCS#12 Bundle

```php
use CA\Pkcs12\Facades\CaPkcs12;

$bundle = CaPkcs12::create(
    cert: $certificate,
    key: $privateKey,
    password: 'secure-password',
    friendlyName: 'My Certificate',
);
```

### Exporting a PKCS#12 Bundle to DER

```php
$pfxDer = CaPkcs12::export(bundle: $bundle, password: 'secure-password');

// Save as .p12 file
file_put_contents('certificate.p12', $pfxDer);
```

### Parsing / Importing an Existing .p12 File

```php
$pfxData = file_get_contents('certificate.p12');

$result = CaPkcs12::parse(pkcs12Der: $pfxData, password: 'secure-password');

// $result['privateKey']   — PEM-encoded private key
// $result['certificate']  — PEM-encoded end-entity certificate
// $result['chain']        — array of PEM-encoded chain certificates
```

### Using the Encoder Directly (Low-Level)

```php
use CA\Pkcs12\Asn1\Pkcs12Encoder;

$encoder = app(Pkcs12Encoder::class);

$pfxDer = $encoder->encode(
    privateKeyDer: $privateKeyDer,
    certificateDer: $certDer,
    chainCertsDer: $chainCertsDer,
    password: 'password',
    options: [
        'encryption_algorithm' => 'aes-256-cbc',
        'mac_algorithm' => 'sha256',
        'legacy' => false,
    ],
);
```

### Using the Decoder Directly (Low-Level)

```php
use CA\Pkcs12\Asn1\Pkcs12Decoder;

$decoder = app(Pkcs12Decoder::class);

$result = $decoder->decode(pfxDer: $pfxData, password: 'password');
```

### Password-Based Encryption

```php
use CA\Pkcs12\Crypto\PbeEncryption;

$pbe = app(PbeEncryption::class);

// Modern mode (PBES2 with PBKDF2-HMAC-SHA256 + AES-256-CBC)
$result = $pbe->encrypt(
    data: $plaintext,
    password: 'password',
    algorithm: 'aes-256-cbc',
    iterations: 2048,
);

$decrypted = $pbe->decrypt(
    data: $result['encrypted'],
    password: 'password',
    salt: $result['salt'],
    iv: $result['iv'],
    algorithm: 'aes-256-cbc',
    iterations: 2048,
);

// Legacy mode (PBE-SHA1-3DES, PKCS#12 v1 KDF)
$result = $pbe->encrypt(
    data: $plaintext,
    password: 'password',
    legacy: true,
);
```

### Artisan Commands

```bash
# Create a PKCS#12 bundle for a certificate
php artisan ca-pkcs12:create {certificate_id} --password=secret

# Export a PKCS#12 bundle to a file
php artisan ca-pkcs12:export {bundle_uuid} --output=certificate.p12

# Import a .p12/.pfx file
php artisan ca-pkcs12:import {file_path} --password=secret
```

### API Routes

When routes are enabled (`ca-pkcs12.routes.enabled = true`), the following endpoints are available under the configured prefix:

| Method | URI | Description |
|---|---|---|
| `POST` | `/api/ca/pkcs12` | Create a new PKCS#12 bundle |
| `GET` | `/api/ca/pkcs12/{uuid}` | Get bundle metadata |
| `POST` | `/api/ca/pkcs12/{uuid}/export` | Export bundle as .p12 binary |

## Testing

```bash
./vendor/bin/pest
./vendor/bin/pint --test
./vendor/bin/phpstan analyse
```

## Changelog

Please see [CHANGELOG.md](CHANGELOG.md) for more information on what has changed recently.

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Security

If you discover a security vulnerability, please see [SECURITY.md](SECURITY.md). Do **not** open a public issue.

## Credits

- [Groupesti](https://github.com/groupesti)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [LICENSE.md](LICENSE.md) for more information.
