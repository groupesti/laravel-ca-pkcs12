<?php

declare(strict_types=1);

namespace CA\Pkcs12\Contracts;

use CA\Crt\Models\Certificate;
use CA\Key\Models\Key;

interface Pkcs12BuilderInterface
{
    /**
     * Set the certificate for the PKCS#12 bundle.
     */
    public function certificate(Certificate $certificate): static;

    /**
     * Set the private key for the PKCS#12 bundle.
     */
    public function key(Key $key): static;

    /**
     * Set the password for encryption.
     */
    public function password(string $password): static;

    /**
     * Set the certificate chain.
     *
     * @param array<int, Certificate> $chain
     */
    public function chain(array $chain): static;

    /**
     * Set the friendly name (alias) for the bundle.
     */
    public function friendlyName(string $friendlyName): static;

    /**
     * Set the encryption algorithm.
     */
    public function encryptionAlgorithm(string $algorithm): static;

    /**
     * Set the MAC algorithm.
     */
    public function macAlgorithm(string $algorithm): static;

    /**
     * Enable or disable legacy compatibility mode (3DES + SHA1).
     */
    public function legacy(bool $legacy = true): static;

    /**
     * Build the PKCS#12 structure and return DER bytes.
     */
    public function build(): string;
}
