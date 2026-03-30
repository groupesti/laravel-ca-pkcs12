<?php

declare(strict_types=1);

namespace CA\Pkcs12\Console\Commands;

use CA\Pkcs12\Contracts\Pkcs12ManagerInterface;
use Illuminate\Console\Command;

class Pkcs12ImportCommand extends Command
{
    protected $signature = 'ca:pkcs12:import
        {file : Path to the PKCS#12 (.p12/.pfx) file}
        {--password= : Password to decrypt (prompted if not given)}';

    protected $description = 'Parse and display the contents of a PKCS#12 file';

    public function handle(Pkcs12ManagerInterface $manager): int
    {
        $filePath = $this->argument('file');

        if (!file_exists($filePath)) {
            $this->error("File not found: {$filePath}");
            return self::FAILURE;
        }

        $password = $this->option('password') ?? $this->secret('Enter password');

        if ($password === null) {
            $this->error('Password is required.');
            return self::FAILURE;
        }

        $data = file_get_contents($filePath);

        if ($data === false || $data === '') {
            $this->error('Failed to read file or file is empty.');
            return self::FAILURE;
        }

        try {
            $result = $manager->parse($data, $password);
        } catch (\Throwable $e) {
            $this->error("Failed to parse PKCS#12 file: {$e->getMessage()}");
            return self::FAILURE;
        }

        $this->info('PKCS#12 file parsed successfully.');
        $this->newLine();

        $this->line('<fg=cyan>Private Key:</>');
        $this->line($result['privateKey'] ? 'Present' : 'Not found');
        $this->newLine();

        $this->line('<fg=cyan>Certificate:</>');
        if ($result['certificate']) {
            $this->line($result['certificate']);
        } else {
            $this->line('Not found');
        }
        $this->newLine();

        $chainCount = count($result['chain']);
        $this->line("<fg=cyan>Chain Certificates:</> {$chainCount}");

        foreach ($result['chain'] as $index => $chainCert) {
            $this->newLine();
            $this->line("<fg=yellow>Chain Certificate #{$index}:</>");
            $this->line($chainCert);
        }

        return self::SUCCESS;
    }
}
