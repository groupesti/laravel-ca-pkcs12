<?php

declare(strict_types=1);

namespace CA\Pkcs12\Contracts;

use CA\Crt\Models\Certificate;
use CA\Key\Models\Key;
use CA\Pkcs12\Models\Pkcs12Bundle;

interface Pkcs12ManagerInterface
{
    /**
     * Create a new PKCS#12 bundle from a certificate and key.
     *
     * @param array<int, Certificate> $chainCerts
     */
    public function create(
        Certificate $cert,
        Key $key,
        string $password,
        array $chainCerts = [],
        ?string $friendlyName = null,
    ): Pkcs12Bundle;

    /**
     * Parse a PKCS#12 DER binary and extract its contents.
     *
     * @return array{privateKey: string, certificate: string, chain: array<int, string>}
     */
    public function parse(string $pkcs12Der, string $password): array;

    /**
     * Export a PKCS#12 bundle as DER binary with the given password.
     */
    public function export(Pkcs12Bundle $bundle, string $password): string;

    /**
     * Find a PKCS#12 bundle by UUID.
     */
    public function findByUuid(string $uuid): ?Pkcs12Bundle;
}
