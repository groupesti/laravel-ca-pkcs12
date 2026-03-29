<?php

declare(strict_types=1);

namespace CA\Pkcs12\Asn1\Maps;

use phpseclib3\File\ASN1;

/**
 * PFX ::= SEQUENCE {
 *     version     INTEGER {v3(3)}(v3,...),
 *     authSafe    ContentInfo,
 *     macData     MacData OPTIONAL
 * }
 */
final class PFX
{
    public static function getMap(): array
    {
        return [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'version' => [
                    'type' => ASN1::TYPE_INTEGER,
                ],
                'authSafe' => PKCS7::getContentInfoMap(),
                'macData' => MacData::getMap() + ['optional' => true],
            ],
        ];
    }
}
