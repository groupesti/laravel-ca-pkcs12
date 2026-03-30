<?php

declare(strict_types=1);

namespace CA\Pkcs12\Events;

use Illuminate\Foundation\Events\Dispatchable;

final class Pkcs12Exported
{
    use Dispatchable;

    public function __construct(
        public readonly string $bundleUuid,
    ) {}
}
