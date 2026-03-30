<?php

declare(strict_types=1);

namespace CA\Pkcs12\Console\Commands;

use CA\Pkcs12\Contracts\Pkcs12ManagerInterface;
use Illuminate\Console\Command;

class Pkcs12ExportCommand extends Command
{
    protected $signature = 'ca:pkcs12:export
        {uuid : UUID of the PKCS#12 bundle}
        {--password= : Password for export (prompted if not given)}
        {--output= : Output file path}';

    protected $description = 'Export a PKCS#12 bundle as a .p12 file';

    public function handle(Pkcs12ManagerInterface $manager): int
    {
        $uuid = $this->argument('uuid');
        $bundle = $manager->findByUuid($uuid);

        if ($bundle === null) {
            $this->error("PKCS#12 bundle not found: {$uuid}");
            return self::FAILURE;
        }

        $password = $this->option('password') ?? $this->secret('Enter password for export');

        if (empty($password)) {
            $this->error('Password is required.');
            return self::FAILURE;
        }

        if (strlen($password) < 8) {
            $this->error('Password must be at least 8 characters.');
            return self::FAILURE;
        }

        try {
            $der = $manager->export($bundle, $password);
        } catch (\Throwable $e) {
            $this->error("Failed to export PKCS#12 bundle: {$e->getMessage()}");
            return self::FAILURE;
        }

        $outputPath = $this->option('output')
            ?? ($bundle->friendly_name ?? $bundle->uuid) . '.p12';

        file_put_contents($outputPath, $der);

        $this->info("PKCS#12 bundle exported to: {$outputPath}");
        $this->line(sprintf('File size: %s bytes', number_format(strlen($der))));

        return self::SUCCESS;
    }
}
