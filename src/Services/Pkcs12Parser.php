<?php

declare(strict_types=1);

namespace CA\Pkcs12\Services;

use CA\Pkcs12\Asn1\Pkcs12Decoder;
use RuntimeException;

/**
 * High-level wrapper around Pkcs12Decoder with validation and error handling.
 */
final class Pkcs12Parser
{
    public function __construct(
        private readonly Pkcs12Decoder $decoder,
    ) {}

    /**
     * Parse a PKCS#12 file and return its contents.
     *
     * @param string $pkcs12Data PKCS#12 DER or base64 data
     * @param string $password   Password to decrypt
     * @return array{privateKey: string, certificate: string, chain: array<int, string>}
     *
     * @throws RuntimeException If parsing fails
     */
    public function parse(string $pkcs12Data, string $password): array
    {
        // Auto-detect base64 encoding
        $decoded = base64_decode($pkcs12Data, true);
        if ($decoded !== false && $this->looksLikeDer($decoded)) {
            $pkcs12Data = $decoded;
        }

        $this->validateInput($pkcs12Data);

        try {
            $result = $this->decoder->decode($pkcs12Data, $password);
        } catch (RuntimeException $e) {
            throw new RuntimeException(
                "Failed to parse PKCS#12 bundle: {$e->getMessage()}",
                previous: $e,
            );
        }

        $this->validateResult($result);

        return $result;
    }

    /**
     * Check if a string looks like DER-encoded data (starts with ASN.1 SEQUENCE tag).
     */
    private function looksLikeDer(string $data): bool
    {
        return strlen($data) > 2 && ord($data[0]) === 0x30;
    }

    /**
     * Validate input data.
     */
    private function validateInput(string $data): void
    {
        if ($data === '') {
            throw new RuntimeException('PKCS#12 data is empty');
        }

        if (strlen($data) < 20) {
            throw new RuntimeException('PKCS#12 data is too short to be valid');
        }

        // Must start with ASN.1 SEQUENCE tag
        if (ord($data[0]) !== 0x30) {
            throw new RuntimeException(
                'Invalid PKCS#12 data: does not start with ASN.1 SEQUENCE tag'
            );
        }
    }

    /**
     * Validate parsed result.
     */
    private function validateResult(array $result): void
    {
        if (empty($result['privateKey'])) {
            throw new RuntimeException('PKCS#12 bundle does not contain a private key');
        }

        if (empty($result['certificate'])) {
            throw new RuntimeException('PKCS#12 bundle does not contain a certificate');
        }

        // Verify PEM format
        if (!str_contains($result['certificate'], '-----BEGIN CERTIFICATE-----')) {
            throw new RuntimeException('Extracted certificate is not in valid PEM format');
        }
    }
}
