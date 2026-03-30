<?php

declare(strict_types=1);

namespace CA\Pkcs12\Events;

use CA\Pkcs12\Models\Pkcs12Bundle;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

final class Pkcs12Created
{
    use Dispatchable;
    use SerializesModels;

    public function __construct(
        public readonly Pkcs12Bundle $bundle,
    ) {}
}
