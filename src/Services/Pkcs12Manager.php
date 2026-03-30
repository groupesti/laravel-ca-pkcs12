<?php

declare(strict_types=1);

namespace CA\Pkcs12\Services;

use CA\Crt\Models\Certificate;
use CA\Crt\Services\ChainBuilder;
use CA\Key\Contracts\KeyManagerInterface;
use CA\Key\Models\Key;
use CA\Log\Facades\CaLog;
use CA\Pkcs12\Asn1\Pkcs12Decoder;
use CA\Pkcs12\Asn1\Pkcs12Encoder;
use CA\Pkcs12\Contracts\Pkcs12ManagerInterface;
use CA\Pkcs12\Events\Pkcs12Created;
use CA\Pkcs12\Events\Pkcs12Exported;
use CA\Pkcs12\Models\Pkcs12Bundle;
use RuntimeException;

final class Pkcs12Manager implements Pkcs12ManagerInterface
{
    public function __construct(
        private readonly Pkcs12Encoder $encoder,
        private readonly Pkcs12Decoder $decoder,
        private readonly KeyManagerInterface $keyManager,
        private readonly ChainBuilder $chainBuilder,
    ) {}

    /**
     * {@inheritDoc}
     */
    public function create(
        Certificate $cert,
        Key $key,
        string $password,
        array $chainCerts = [],
        ?string $friendlyName = null,
    ): Pkcs12Bundle {
        $subject = $cert->subject ?? $cert->id;

        try {
            $encAlgo = config('ca-pkcs12.default_encryption', 'aes-256-cbc');
            $macAlgo = config('ca-pkcs12.default_mac', 'sha256');
            $legacy = config('ca-pkcs12.legacy_compatibility', false);
            $includeChain = config('ca-pkcs12.include_chain', true);

            if ($legacy) {
                $encAlgo = '3des-cbc';
                $macAlgo = 'sha1';
            }

            // Build chain if not provided and include_chain is enabled
            if ($chainCerts === [] && $includeChain) {
                $fullChain = $this->chainBuilder->buildChain($cert);
                // Remove the leaf certificate (first element)
                $chainCerts = array_slice($fullChain, 1);
            }

            // Create the bundle record (no password stored)
            $bundle = Pkcs12Bundle::create([
                'certificate_id' => $cert->id,
                'tenant_id' => $cert->tenant_id,
                'friendly_name' => $friendlyName,
                'include_chain' => $includeChain && $chainCerts !== [],
                'encryption_algorithm' => $encAlgo,
                'mac_algorithm' => $macAlgo,
            ]);

            event(new Pkcs12Created($bundle));

            CaLog::log('pkcs12_create', 'info', "PKCS12 bundle created for: {$subject}", [
                'bundle_id' => $bundle->id,
                'certificate_id' => $cert->id,
                'friendly_name' => $friendlyName,
                'encryption_algorithm' => $encAlgo,
                'include_chain' => $includeChain && $chainCerts !== [],
            ]);

            return $bundle;
        } catch (\Throwable $e) {
            CaLog::critical($e->getMessage(), [
                'operation' => 'pkcs12_create',
                'certificate_id' => $cert->id,
                'exception' => $e::class,
            ]);

            throw $e;
        }
    }

    /**
     * {@inheritDoc}
     */
    public function parse(string $pkcs12Der, string $password): array
    {
        try {
            $result = $this->decoder->decode($pkcs12Der, $password);

            CaLog::log('pkcs12_parse', 'info', 'PKCS12 bundle parsed successfully', [
                'has_private_key' => ! empty($result['privateKey']),
                'has_certificate' => ! empty($result['certificate']),
                'chain_count' => count($result['chain'] ?? []),
            ]);

            return $result;
        } catch (\Throwable $e) {
            CaLog::critical($e->getMessage(), [
                'operation' => 'pkcs12_parse',
                'exception' => $e::class,
            ]);

            throw $e;
        }
    }

    /**
     * {@inheritDoc}
     */
    public function export(Pkcs12Bundle $bundle, string $password): string
    {
        $subject = $bundle->certificate?->subject ?? $bundle->certificate_id;

        try {
            $cert = $bundle->certificate;
            if ($cert === null) {
                throw new RuntimeException('Certificate not found for PKCS#12 bundle');
            }

            $key = $cert->key;
            if ($key === null) {
                throw new RuntimeException('Key not found for certificate');
            }

            // Get certificate DER
            $certDer = $cert->certificate_der;
            if ($certDer === null && $cert->certificate_pem !== null) {
                $certDer = $this->pemToDer($cert->certificate_pem);
            }

            if ($certDer === null) {
                throw new RuntimeException('Certificate DER data not available');
            }

            // Decrypt private key to get PKCS#8 DER
            $privateKeyObj = $this->keyManager->decryptPrivateKey($key);
            $privateKeyPem = $privateKeyObj->toString('PKCS8');
            $privateKeyDer = $this->pemToDer($privateKeyPem);

            // Build chain
            $chainCertsDer = [];
            if ($bundle->include_chain) {
                $fullChain = $this->chainBuilder->buildChain($cert);
                foreach (array_slice($fullChain, 1) as $chainCert) {
                    $chainDer = $chainCert->certificate_der;
                    if ($chainDer === null && $chainCert->certificate_pem !== null) {
                        $chainDer = $this->pemToDer($chainCert->certificate_pem);
                    }
                    if ($chainDer !== null) {
                        $chainCertsDer[] = $chainDer;
                    }
                }
            }

            $legacy = config('ca-pkcs12.legacy_compatibility', false);

            $der = $this->encoder->encode(
                privateKeyDer: $privateKeyDer,
                certificateDer: $certDer,
                chainCertsDer: $chainCertsDer,
                password: $password,
                options: [
                    'encryption_algorithm' => $bundle->encryption_algorithm,
                    'mac_algorithm' => $bundle->mac_algorithm,
                    'mac_iterations' => config('ca-pkcs12.mac_iterations', 2048),
                    'kdf_iterations' => config('ca-pkcs12.kdf_iterations', 2048),
                    'friendly_name' => $bundle->friendly_name,
                    'legacy' => $legacy,
                ],
            );

            event(new Pkcs12Exported($bundle->uuid));

            CaLog::log('pkcs12_export', 'info', "PKCS12 bundle exported for: {$subject}", [
                'bundle_id' => $bundle->id,
                'bundle_uuid' => $bundle->uuid,
                'certificate_id' => $bundle->certificate_id,
                'encryption_algorithm' => $bundle->encryption_algorithm,
                'include_chain' => $bundle->include_chain,
                'chain_count' => count($chainCertsDer),
            ]);

            return $der;
        } catch (\Throwable $e) {
            CaLog::critical($e->getMessage(), [
                'operation' => 'pkcs12_export',
                'bundle_id' => $bundle->id,
                'bundle_uuid' => $bundle->uuid,
                'exception' => $e::class,
            ]);

            throw $e;
        }
    }

    /**
     * {@inheritDoc}
     */
    public function findByUuid(string $uuid): ?Pkcs12Bundle
    {
        return Pkcs12Bundle::where('uuid', $uuid)->first();
    }

    /**
     * Convert PEM to DER.
     */
    private function pemToDer(string $pem): string
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
