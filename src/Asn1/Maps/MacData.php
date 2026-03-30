<?php

declare(strict_types=1);

namespace CA\Pkcs12\Asn1\Maps;

use phpseclib3\File\ASN1;

/**
 * MacData ::= SEQUENCE {
 *     mac         DigestInfo,
 *     macSalt     OCTET STRING,
 *     iterations  INTEGER DEFAULT 1
 * }
 *
 * DigestInfo ::= SEQUENCE {
 *     digestAlgorithm  AlgorithmIdentifier,
 *     digest           OCTET STRING
 * }
 */
final class MacData
{
    public static function getMap(): array
    {
        return [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'mac' => self::getDigestInfoMap(),
                'macSalt' => [
                    'type' => ASN1::TYPE_OCTET_STRING,
                ],
                'iterations' => [
                    'type' => ASN1::TYPE_INTEGER,
                    'optional' => true,
                    'default' => '1',
                ],
            ],
        ];
    }

    public static function getDigestInfoMap(): array
    {
        return [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'digestAlgorithm' => self::getAlgorithmIdentifierMap(),
                'digest' => [
                    'type' => ASN1::TYPE_OCTET_STRING,
                ],
            ],
        ];
    }

    public static function getAlgorithmIdentifierMap(): array
    {
        return [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'algorithm' => [
                    'type' => ASN1::TYPE_OBJECT_IDENTIFIER,
                ],
                'parameters' => [
                    'type' => ASN1::TYPE_ANY,
                    'optional' => true,
                ],
            ],
        ];
    }
}
