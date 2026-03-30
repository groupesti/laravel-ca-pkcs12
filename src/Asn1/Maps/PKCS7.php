<?php

declare(strict_types=1);

namespace CA\Pkcs12\Asn1\Maps;

use phpseclib3\File\ASN1;

/**
 * Minimal PKCS#7 ContentInfo structures for PKCS#12.
 *
 * ContentInfo ::= SEQUENCE {
 *     contentType  ContentType,
 *     content      [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
 * }
 *
 * ContentType ::= OBJECT IDENTIFIER
 */
final class PKCS7
{
    /** PKCS#7 data */
    public const OID_DATA = '1.2.840.113549.1.7.1';

    /** PKCS#7 encryptedData */
    public const OID_ENCRYPTED_DATA = '1.2.840.113549.1.7.6';

    /** PBE with SHA and 3-Key Triple-DES CBC (PKCS#12 v1) */
    public const OID_PBE_SHA1_3DES = '1.2.840.113549.1.12.1.3';

    /** PBE with SHA and 40-bit RC2-CBC (PKCS#12 v1) */
    public const OID_PBE_SHA1_RC2_40 = '1.2.840.113549.1.12.1.6';

    /** PBES2 (PKCS#5 v2.1) */
    public const OID_PBES2 = '1.2.840.113549.1.5.13';

    /** PBKDF2 */
    public const OID_PBKDF2 = '1.2.840.113549.1.5.12';

    /** AES-256-CBC */
    public const OID_AES_256_CBC = '2.16.840.1.101.3.4.1.42';

    /** AES-128-CBC */
    public const OID_AES_128_CBC = '2.16.840.1.101.3.4.1.2';

    /** 3DES-CBC (DES-EDE3-CBC) */
    public const OID_DES_EDE3_CBC = '1.2.840.113549.3.7';

    /** HMAC-SHA256 */
    public const OID_HMAC_SHA256 = '1.2.840.113549.2.9';

    /** HMAC-SHA1 */
    public const OID_HMAC_SHA1 = '1.2.840.113549.2.7';

    /** Hash algorithm OIDs */
    public const OID_SHA1 = '1.3.14.3.2.26';
    public const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
    public const OID_SHA384 = '2.16.840.1.101.3.4.2.2';
    public const OID_SHA512 = '2.16.840.1.101.3.4.2.3';

    public static function getContentInfoMap(): array
    {
        return [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'contentType' => [
                    'type' => ASN1::TYPE_OBJECT_IDENTIFIER,
                ],
                'content' => [
                    'type' => ASN1::TYPE_ANY,
                    'constant' => 0,
                    'explicit' => true,
                    'optional' => true,
                ],
            ],
        ];
    }

    /**
     * EncryptedData ::= SEQUENCE {
     *     version                Version,
     *     encryptedContentInfo   EncryptedContentInfo
     * }
     *
     * EncryptedContentInfo ::= SEQUENCE {
     *     contentType            ContentType,
     *     contentEncryptionAlgorithm  AlgorithmIdentifier,
     *     encryptedContent       [0] IMPLICIT OCTET STRING OPTIONAL
     * }
     */
    public static function getEncryptedDataMap(): array
    {
        return [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'version' => [
                    'type' => ASN1::TYPE_INTEGER,
                ],
                'encryptedContentInfo' => [
                    'type' => ASN1::TYPE_SEQUENCE,
                    'children' => [
                        'contentType' => [
                            'type' => ASN1::TYPE_OBJECT_IDENTIFIER,
                        ],
                        'contentEncryptionAlgorithm' => MacData::getAlgorithmIdentifierMap(),
                        'encryptedContent' => [
                            'type' => ASN1::TYPE_OCTET_STRING,
                            'constant' => 0,
                            'implicit' => true,
                            'optional' => true,
                        ],
                    ],
                ],
            ],
        ];
    }
}
