<?php

declare(strict_types=1);

namespace CA\Pkcs12\Crypto;

use phpseclib3\Crypt\AES;
use phpseclib3\Crypt\Hash;
use phpseclib3\Crypt\Random;
use phpseclib3\Crypt\TripleDES;
use RuntimeException;

/**
 * Password-Based Encryption for PKCS#12.
 *
 * Supports two modes:
 * - Modern: PBES2 with PBKDF2-HMAC-SHA256 + AES-256-CBC (or AES-128-CBC)
 * - Legacy: PBE-SHA1-3DES (PKCS#12 v1 KDF, pbeWithSHAAnd3-KeyTripleDES-CBC)
 */
final class PbeEncryption
{
    /** Encryption algorithm key sizes in bytes */
    private const KEY_SIZES = [
        'aes-256-cbc' => 32,
        'aes-128-cbc' => 16,
        '3des-cbc'    => 24,
    ];

    /** Encryption algorithm IV sizes in bytes */
    private const IV_SIZES = [
        'aes-256-cbc' => 16,
        'aes-128-cbc' => 16,
        '3des-cbc'    => 8,
    ];

    private const SALT_LENGTH = 8;

    public function __construct(
        private readonly MacCalculator $macCalculator = new MacCalculator(),
    ) {}

    /**
     * Encrypt data using PBE.
     *
     * @param string $data       Plaintext data
     * @param string $password   Password
     * @param string $algorithm  Encryption algorithm (aes-256-cbc, aes-128-cbc, 3des-cbc)
     * @param int    $iterations KDF iterations
     * @param bool   $legacy     If true, use PKCS#12 v1 PBE (SHA1+3DES)
     * @return array{encrypted: string, salt: string, iv: string, algorithm: string}
     */
    public function encrypt(
        string $data,
        string $password,
        string $algorithm = 'aes-256-cbc',
        int $iterations = 2048,
        bool $legacy = false,
    ): array {
        $salt = Random::string(self::SALT_LENGTH);

        if ($legacy) {
            return $this->encryptLegacy($data, $password, $salt, $iterations);
        }

        return $this->encryptModern($data, $password, $salt, $algorithm, $iterations);
    }

    /**
     * Decrypt data using PBE.
     *
     * @param string $data       Encrypted data
     * @param string $password   Password
     * @param string $salt       Salt bytes
     * @param string $iv         IV bytes
     * @param string $algorithm  Encryption algorithm
     * @param int    $iterations KDF iterations
     * @param bool   $legacy     If true, use PKCS#12 v1 PBE
     * @return string Decrypted plaintext
     */
    public function decrypt(
        string $data,
        string $password,
        string $salt,
        string $iv,
        string $algorithm = 'aes-256-cbc',
        int $iterations = 2048,
        bool $legacy = false,
    ): string {
        if ($legacy) {
            return $this->decryptLegacy($data, $password, $salt, $iv, $iterations);
        }

        return $this->decryptModern($data, $password, $salt, $iv, $algorithm, $iterations);
    }

    /**
     * Derive a key using PBKDF2-HMAC-SHA256 (modern mode).
     */
    public function deriveKeyPbkdf2(
        string $password,
        string $salt,
        int $iterations,
        int $keyLength,
        string $hash = 'sha256',
    ): string {
        $hmac = new Hash($hash);
        $hmac->setKey($password);

        $hashLen = match ($hash) {
            'sha256' => 32,
            'sha384' => 48,
            'sha512' => 64,
            'sha1'   => 20,
            default  => throw new RuntimeException("Unsupported PBKDF2 hash: {$hash}"),
        };

        $blocks = (int) ceil($keyLength / $hashLen);
        $derived = '';

        for ($i = 1; $i <= $blocks; $i++) {
            // U_1 = HMAC(password, salt || INT_32_BE(i))
            $u = $hmac->hash($salt . pack('N', $i));
            $result = $u;

            // U_j = HMAC(password, U_{j-1})
            for ($j = 1; $j < $iterations; $j++) {
                $u = $hmac->hash($u);
                $result ^= $u;
            }

            $derived .= $result;
        }

        return substr($derived, 0, $keyLength);
    }

    /**
     * Derive a key using PKCS#12 KDF (legacy mode).
     * Delegates to MacCalculator::pkcs12Kdf.
     */
    public function deriveKey(
        string $password,
        string $salt,
        int $iterations,
        int $keyLength,
        string $hash = 'sha1',
    ): string {
        return $this->macCalculator->pkcs12Kdf(
            password: $password,
            salt: $salt,
            iterations: $iterations,
            keyLength: $keyLength,
            id: 1, // ID=1 for encryption key
            hash: $hash,
        );
    }

    /**
     * Derive an IV using PKCS#12 KDF (legacy mode).
     */
    public function deriveIv(
        string $password,
        string $salt,
        int $iterations,
        int $ivLength,
        string $hash = 'sha1',
    ): string {
        return $this->macCalculator->pkcs12Kdf(
            password: $password,
            salt: $salt,
            iterations: $iterations,
            keyLength: $ivLength,
            id: 2, // ID=2 for IV
            hash: $hash,
        );
    }

    /**
     * Encrypt using modern PBES2 (PBKDF2-HMAC-SHA256 + AES-CBC).
     *
     * @return array{encrypted: string, salt: string, iv: string, algorithm: string}
     */
    private function encryptModern(
        string $data,
        string $password,
        string $salt,
        string $algorithm,
        int $iterations,
    ): array {
        $keySize = self::KEY_SIZES[$algorithm]
            ?? throw new RuntimeException("Unsupported algorithm: {$algorithm}");
        $ivSize = self::IV_SIZES[$algorithm]
            ?? throw new RuntimeException("Unsupported algorithm: {$algorithm}");

        $iv = Random::string($ivSize);

        $key = $this->deriveKeyPbkdf2($password, $salt, $iterations, $keySize, 'sha256');

        $cipher = $this->createCipher($algorithm);
        $cipher->setKey($key);
        $cipher->setIV($iv);

        $encrypted = $cipher->encrypt($data);

        return [
            'encrypted' => $encrypted,
            'salt' => $salt,
            'iv' => $iv,
            'algorithm' => $algorithm,
        ];
    }

    /**
     * Decrypt using modern PBES2.
     */
    private function decryptModern(
        string $data,
        string $password,
        string $salt,
        string $iv,
        string $algorithm,
        int $iterations,
    ): string {
        $keySize = self::KEY_SIZES[$algorithm]
            ?? throw new RuntimeException("Unsupported algorithm: {$algorithm}");

        $key = $this->deriveKeyPbkdf2($password, $salt, $iterations, $keySize, 'sha256');

        $cipher = $this->createCipher($algorithm);
        $cipher->setKey($key);
        $cipher->setIV($iv);

        return $cipher->decrypt($data);
    }

    /**
     * Encrypt using legacy PBE-SHA1-3DES (PKCS#12 v1 KDF).
     *
     * @return array{encrypted: string, salt: string, iv: string, algorithm: string}
     */
    private function encryptLegacy(
        string $data,
        string $password,
        string $salt,
        int $iterations,
    ): array {
        $key = $this->deriveKey($password, $salt, $iterations, 24, 'sha1');
        $iv = $this->deriveIv($password, $salt, $iterations, 8, 'sha1');

        $cipher = new TripleDES('cbc');
        $cipher->setKey($key);
        $cipher->setIV($iv);
        $cipher->disablePadding();

        // PKCS#7 padding
        $padded = self::pkcs7Pad($data, 8);
        $encrypted = $cipher->encrypt($padded);

        return [
            'encrypted' => $encrypted,
            'salt' => $salt,
            'iv' => $iv,
            'algorithm' => '3des-cbc',
        ];
    }

    /**
     * Decrypt using legacy PBE-SHA1-3DES.
     */
    private function decryptLegacy(
        string $data,
        string $password,
        string $salt,
        string $iv,
        int $iterations,
    ): string {
        $key = $this->deriveKey($password, $salt, $iterations, 24, 'sha1');
        // For legacy PKCS#12, IV is derived from KDF, not from the passed $iv
        $derivedIv = $this->deriveIv($password, $salt, $iterations, 8, 'sha1');

        $cipher = new TripleDES('cbc');
        $cipher->setKey($key);
        $cipher->setIV($derivedIv);
        $cipher->disablePadding();

        $decrypted = $cipher->decrypt($data);

        return self::pkcs7Unpad($decrypted);
    }

    /**
     * Create a phpseclib cipher instance.
     */
    private function createCipher(string $algorithm): AES|TripleDES
    {
        return match ($algorithm) {
            'aes-256-cbc', 'aes-128-cbc' => new AES('cbc'),
            '3des-cbc' => new TripleDES('cbc'),
            default => throw new RuntimeException("Unsupported cipher: {$algorithm}"),
        };
    }

    /**
     * Apply PKCS#7 padding.
     */
    private static function pkcs7Pad(string $data, int $blockSize): string
    {
        $padding = $blockSize - (strlen($data) % $blockSize);

        return $data . str_repeat(chr($padding), $padding);
    }

    /**
     * Remove PKCS#7 padding.
     */
    private static function pkcs7Unpad(string $data, int $blockSize = 8): string
    {
        if ($data === '') {
            return $data;
        }

        $padding = ord($data[strlen($data) - 1]);

        if ($padding < 1 || $padding > $blockSize) {
            throw new RuntimeException('Invalid PKCS#7 padding');
        }

        // Verify all padding bytes
        for ($i = 0; $i < $padding; $i++) {
            if (ord($data[strlen($data) - 1 - $i]) !== $padding) {
                throw new RuntimeException('Invalid PKCS#7 padding');
            }
        }

        return substr($data, 0, -$padding);
    }
}
