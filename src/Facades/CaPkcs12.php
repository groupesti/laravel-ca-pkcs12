<?php

declare(strict_types=1);

namespace CA\Pkcs12\Facades;

use CA\Pkcs12\Contracts\Pkcs12ManagerInterface;
use Illuminate\Support\Facades\Facade;

/**
 * @method static \CA\Pkcs12\Models\Pkcs12Bundle create(\CA\Crt\Models\Certificate $cert, \CA\Key\Models\Key $key, string $password, array $chainCerts = [], ?string $friendlyName = null)
 * @method static array parse(string $pkcs12Der, string $password)
 * @method static string export(\CA\Pkcs12\Models\Pkcs12Bundle $bundle, string $password)
 * @method static \CA\Pkcs12\Models\Pkcs12Bundle|null findByUuid(string $uuid)
 *
 * @see \CA\Pkcs12\Services\Pkcs12Manager
 */
final class CaPkcs12 extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return Pkcs12ManagerInterface::class;
    }
}
