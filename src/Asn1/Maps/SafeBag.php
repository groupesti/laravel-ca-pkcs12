<?php

declare(strict_types=1);

namespace CA\Pkcs12\Asn1\Maps;

use phpseclib3\File\ASN1;

/**
 * SafeBag ::= SEQUENCE {
 *     bagId          OBJECT IDENTIFIER,
 *     bagValue       [0] EXPLICIT ANY DEFINED BY bagId,
 *     bagAttributes  SET OF PKCS12Attribute OPTIONAL
 * }
 *
 * Bag types:
 *   keyBag               1.2.840.113549.1.12.10.1.1
 *   pkcs8ShroudedKeyBag  1.2.840.113549.1.12.10.1.2
 *   certBag              1.2.840.113549.1.12.10.1.3
 *   crlBag               1.2.840.113549.1.12.10.1.4
 *   secretBag            1.2.840.113549.1.12.10.1.5
 *   safeContentsBag      1.2.840.113549.1.12.10.1.6
 */
final class SafeBag
{
    public const BAG_KEY = '1.2.840.113549.1.12.10.1.1';
    public const BAG_PKCS8_SHROUDED_KEY = '1.2.840.113549.1.12.10.1.2';
    public const BAG_CERT = '1.2.840.113549.1.12.10.1.3';
    public const BAG_CRL = '1.2.840.113549.1.12.10.1.4';
    public const BAG_SECRET = '1.2.840.113549.1.12.10.1.5';
    public const BAG_SAFE_CONTENTS = '1.2.840.113549.1.12.10.1.6';

    /** CertBag OID for X.509 certificates */
    public const CERT_X509 = '1.2.840.113549.1.9.22.1';

    /** PKCS#9 friendlyName */
    public const ATTR_FRIENDLY_NAME = '1.2.840.113549.1.9.20';

    /** PKCS#9 localKeyId */
    public const ATTR_LOCAL_KEY_ID = '1.2.840.113549.1.9.21';

    public static function getMap(): array
    {
        return [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'bagId' => [
                    'type' => ASN1::TYPE_OBJECT_IDENTIFIER,
                ],
                'bagValue' => [
                    'type' => ASN1::TYPE_ANY,
                    'constant' => 0,
                    'explicit' => true,
                ],
                'bagAttributes' => [
                    'type' => ASN1::TYPE_SET,
                    'min' => 0,
                    'max' => -1,
                    'optional' => true,
                    'children' => self::getPkcs12AttributeMap(),
                ],
            ],
        ];
    }

    public static function getPkcs12AttributeMap(): array
    {
        return [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'attrId' => [
                    'type' => ASN1::TYPE_OBJECT_IDENTIFIER,
                ],
                'attrValues' => [
                    'type' => ASN1::TYPE_SET,
                    'min' => 0,
                    'max' => -1,
                    'children' => [
                        'type' => ASN1::TYPE_ANY,
                    ],
                ],
            ],
        ];
    }

    public static function getCertBagMap(): array
    {
        return [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'certId' => [
                    'type' => ASN1::TYPE_OBJECT_IDENTIFIER,
                ],
                'certValue' => [
                    'type' => ASN1::TYPE_ANY,
                    'constant' => 0,
                    'explicit' => true,
                ],
            ],
        ];
    }
}
