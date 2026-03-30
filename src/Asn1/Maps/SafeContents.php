<?php

declare(strict_types=1);

namespace CA\Pkcs12\Asn1\Maps;

use phpseclib3\File\ASN1;

/**
 * SafeContents ::= SEQUENCE OF SafeBag
 */
final class SafeContents
{
    public static function getMap(): array
    {
        return [
            'type' => ASN1::TYPE_SEQUENCE,
            'min' => 0,
            'max' => -1,
            'children' => SafeBag::getMap(),
        ];
    }
}
