<?php

declare(strict_types=1);

namespace CA\Pkcs12\Asn1\Maps;

use phpseclib3\File\ASN1;

/**
 * AuthenticatedSafe ::= SEQUENCE OF ContentInfo
 *     -- Data if unencrypted
 *     -- EncryptedData if password-encrypted
 *     -- EnvelopedData if public key-encrypted
 */
final class AuthenticatedSafe
{
    public static function getMap(): array
    {
        return [
            'type' => ASN1::TYPE_SEQUENCE,
            'min' => 0,
            'max' => -1,
            'children' => PKCS7::getContentInfoMap(),
        ];
    }
}
