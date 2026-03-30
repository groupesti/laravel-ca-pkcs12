<?php

declare(strict_types=1);

namespace CA\Pkcs12\Console\Commands;

use CA\Crt\Models\Certificate;
use CA\Pkcs12\Contracts\Pkcs12ManagerInterface;
use Illuminate\Console\Command;

class Pkcs12CreateCommand extends Command
{
    protected $signature = 'ca:pkcs12:create
        {cert_uuid : UUID of the certificate}
        {--password= : Password for the PKCS#12 bundle (prompted if not given)}
        {--friendly-name= : Friendly name / alias}
        {--no-chain : Exclude certificate chain}
        {--legacy : Use legacy 3DES+SHA1 for compatibility}';

    protected $description = 'Create a PKCS#12 bundle from a certificate';

    public function handle(Pkcs12ManagerInterface $manager): int
    {
        $certUuid = $this->argument('cert_uuid');

        $cert = Certificate::where('uuid', $certUuid)->first();

        if ($cert === null) {
            $this->error("Certificate not found: {$certUuid}");
            return self::FAILURE;
        }

        $key = $cert->key;
        if ($key === null) {
            $this->error('No private key associated with this certificate.');
            return self::FAILURE;
        }

        $password = $this->option('password') ?? $this->secret('Enter password for PKCS#12 bundle');

        if (empty($password)) {
            $this->error('Password is required.');
            return self::FAILURE;
        }

        if (strlen($password) < 8) {
            $this->error('Password must be at least 8 characters.');
            return self::FAILURE;
        }

        // Temporarily override config for legacy mode
        if ($this->option('legacy')) {
            config([
                'ca-pkcs12.legacy_compatibility' => true,
            ]);
        }

        if ($this->option('no-chain')) {
            config([
                'ca-pkcs12.include_chain' => false,
            ]);
        }

        try {
            $bundle = $manager->create(
                cert: $cert,
                key: $key,
                password: $password,
                friendlyName: $this->option('friendly-name'),
            );

            $this->info("PKCS#12 bundle created successfully.");
            $this->table(
                ['Field', 'Value'],
                [
                    ['UUID', $bundle->uuid],
                    ['Certificate', $cert->uuid],
                    ['Friendly Name', $bundle->friendly_name ?? '(none)'],
                    ['Encryption', $bundle->encryption_algorithm],
                    ['MAC', $bundle->mac_algorithm],
                    ['Include Chain', $bundle->include_chain ? 'Yes' : 'No'],
                ],
            );

            return self::SUCCESS;
        } catch (\Throwable $e) {
            $this->error("Failed to create PKCS#12 bundle: {$e->getMessage()}");
            return self::FAILURE;
        }
    }
}
