<?php

declare(strict_types=1);

namespace CA\Pkcs12;

use CA\Crt\Services\ChainBuilder;
use CA\Key\Contracts\KeyManagerInterface;
use CA\Pkcs12\Asn1\Pkcs12Decoder;
use CA\Pkcs12\Asn1\Pkcs12Encoder;
use CA\Pkcs12\Console\Commands\Pkcs12CreateCommand;
use CA\Pkcs12\Console\Commands\Pkcs12ExportCommand;
use CA\Pkcs12\Console\Commands\Pkcs12ImportCommand;
use CA\Pkcs12\Contracts\Pkcs12BuilderInterface;
use CA\Pkcs12\Contracts\Pkcs12ManagerInterface;
use CA\Pkcs12\Crypto\MacCalculator;
use CA\Pkcs12\Crypto\PbeEncryption;
use CA\Pkcs12\Services\Pkcs12Builder;
use CA\Pkcs12\Services\Pkcs12Manager;
use CA\Pkcs12\Services\Pkcs12Parser;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;

class Pkcs12ServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/ca-pkcs12.php',
            'ca-pkcs12',
        );

        // Crypto primitives
        $this->app->singleton(MacCalculator::class);
        $this->app->singleton(PbeEncryption::class, function ($app): PbeEncryption {
            return new PbeEncryption(
                macCalculator: $app->make(MacCalculator::class),
            );
        });

        // ASN.1 encoder/decoder
        $this->app->singleton(Pkcs12Encoder::class, function ($app): Pkcs12Encoder {
            return new Pkcs12Encoder(
                pbe: $app->make(PbeEncryption::class),
                macCalculator: $app->make(MacCalculator::class),
            );
        });

        $this->app->singleton(Pkcs12Decoder::class, function ($app): Pkcs12Decoder {
            return new Pkcs12Decoder(
                pbe: $app->make(PbeEncryption::class),
                macCalculator: $app->make(MacCalculator::class),
            );
        });

        // Parser
        $this->app->singleton(Pkcs12Parser::class, function ($app): Pkcs12Parser {
            return new Pkcs12Parser(
                decoder: $app->make(Pkcs12Decoder::class),
            );
        });

        // Builder
        $this->app->bind(Pkcs12BuilderInterface::class, function ($app): Pkcs12Builder {
            return new Pkcs12Builder(
                encoder: $app->make(Pkcs12Encoder::class),
                keyManager: $app->make(KeyManagerInterface::class),
            );
        });

        // Manager
        $this->app->singleton(Pkcs12ManagerInterface::class, function ($app): Pkcs12Manager {
            return new Pkcs12Manager(
                encoder: $app->make(Pkcs12Encoder::class),
                decoder: $app->make(Pkcs12Decoder::class),
                keyManager: $app->make(KeyManagerInterface::class),
                chainBuilder: $app->make(ChainBuilder::class),
            );
        });

        $this->app->alias(Pkcs12ManagerInterface::class, 'ca-pkcs12');
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/ca-pkcs12.php' => config_path('ca-pkcs12.php'),
            ], 'ca-pkcs12-config');

            $this->publishes([
                __DIR__ . '/../database/migrations/' => database_path('migrations'),
            ], 'ca-pkcs12-migrations');

            $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');

            $this->commands([
                Pkcs12CreateCommand::class,
                Pkcs12ExportCommand::class,
                Pkcs12ImportCommand::class,
            ]);
        }

        $this->registerRoutes();
    }

    private function registerRoutes(): void
    {
        if (!config('ca-pkcs12.routes.enabled', true)) {
            return;
        }

        Route::prefix(config('ca-pkcs12.routes.prefix', 'api/ca/pkcs12'))
            ->middleware(config('ca-pkcs12.routes.middleware', ['api']))
            ->group(__DIR__ . '/../routes/api.php');
    }
}
