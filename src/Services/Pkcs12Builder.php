<?php

declare(strict_types=1);

namespace CA\Pkcs12\Services;

use CA\Crt\Models\Certificate;
use CA\Key\Contracts\KeyManagerInterface;
use CA\Key\Models\Key;
use CA\Pkcs12\Asn1\Pkcs12Encoder;
use CA\Pkcs12\Contracts\Pkcs12BuilderInterface;
use RuntimeException;

final class Pkcs12Builder implements Pkcs12BuilderInterface
{
    private ?Certificate $certificate = null;
    private ?Key $key = null;
    private string $password = '';
    private array $chain = [];
    private ?string $friendlyName = null;
    private string $encryptionAlgorithm;
    private string $macAlgorithm;
    private bool $legacy;

    public function __construct(
        private readonly Pkcs12Encoder $encoder,
        private readonly KeyManagerInterface $keyManager,
    ) {
        $this->encryptionAlgorithm = config('ca-pkcs12.default_encryption', 'aes-256-cbc');
        $this->macAlgorithm = config('ca-pkcs12.default_mac', 'sha256');
        $this->legacy = config('ca-pkcs12.legacy_compatibility', false);
    }

    public function certificate(Certificate $certificate): static
    {
        $this->certificate = $certificate;

        return $this;
    }

    public function key(Key $key): static
    {
        $this->key = $key;

        return $this;
    }

    public function password(string $password): static
    {
        $this->password = $password;

        return $this;
    }

    public function chain(array $chain): static
    {
        $this->chain = $chain;

        return $this;
    }

    public function friendlyName(string $friendlyName): static
    {
        $this->friendlyName = $friendlyName;

        return $this;
    }

    public function encryptionAlgorithm(string $algorithm): static
    {
        $this->encryptionAlgorithm = $algorithm;

        return $this;
    }

    public function macAlgorithm(string $algorithm): static
    {
        $this->macAlgorithm = $algorithm;

        return $this;
    }

    public function legacy(bool $legacy = true): static
    {
        $this->legacy = $legacy;

        return $this;
    }

    public function build(): string
    {
        if ($this->certificate === null) {
            throw new RuntimeException('Certificate is required to build PKCS#12');
        }

        if ($this->password === '') {
            throw new RuntimeException('Password is required to build PKCS#12');
        }

        $key = $this->key ?? $this->certificate->key;
        if ($key === null) {
            throw new RuntimeException('Private key is required to build PKCS#12');
        }

        // Get certificate DER
        $certDer = $this->certificate->certificate_der;
        if ($certDer === null && $this->certificate->certificate_pem !== null) {
            $certDer = self::pemToDer($this->certificate->certificate_pem);
        }

        if ($certDer === null) {
            throw new RuntimeException('Certificate DER data not available');
        }

        // Decrypt private key to PKCS#8 DER
        $privateKeyObj = $this->keyManager->decryptPrivateKey($key);
        $privateKeyPem = $privateKeyObj->toString('PKCS8');
        $privateKeyDer = self::pemToDer($privateKeyPem);

        // Build chain DERs
        $chainDers = [];
        foreach ($this->chain as $chainCert) {
            $chainDer = $chainCert->certificate_der;
            if ($chainDer === null && $chainCert->certificate_pem !== null) {
                $chainDer = self::pemToDer($chainCert->certificate_pem);
            }
            if ($chainDer !== null) {
                $chainDers[] = $chainDer;
            }
        }

        return $this->encoder->encode(
            privateKeyDer: $privateKeyDer,
            certificateDer: $certDer,
            chainCertsDer: $chainDers,
            password: $this->password,
            options: [
                'encryption_algorithm' => $this->encryptionAlgorithm,
                'mac_algorithm' => $this->macAlgorithm,
                'mac_iterations' => config('ca-pkcs12.mac_iterations', 2048),
                'kdf_iterations' => config('ca-pkcs12.kdf_iterations', 2048),
                'friendly_name' => $this->friendlyName,
                'legacy' => $this->legacy,
            ],
        );
    }

    private static function pemToDer(string $pem): string
    {
        $pem = preg_replace('/-----[A-Z\s]+-----/', '', $pem);
        $pem = preg_replace('/\s+/', '', $pem);

        $der = base64_decode($pem, true);
        if ($der === false) {
            throw new RuntimeException('Failed to decode PEM to DER');
        }

        return $der;
    }
}
