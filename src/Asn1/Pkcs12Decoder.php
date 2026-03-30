<?php

declare(strict_types=1);

namespace CA\Pkcs12\Asn1;

use CA\Pkcs12\Asn1\Maps\PKCS7;
use CA\Pkcs12\Asn1\Maps\SafeBag;
use CA\Pkcs12\Crypto\MacCalculator;
use CA\Pkcs12\Crypto\PbeEncryption;
use RuntimeException;

/**
 * Decodes PKCS#12 (PFX) DER structures per RFC 7292.
 */
final class Pkcs12Decoder
{
    public function __construct(
        private readonly PbeEncryption $pbe = new PbeEncryption(),
        private readonly MacCalculator $macCalculator = new MacCalculator(),
    ) {}

    /**
     * Decode a PKCS#12 PFX DER structure.
     *
     * @param string $pfxDer   PFX in DER format
     * @param string $password Password
     * @return array{privateKey: string, certificate: string, chain: array<int, string>}
     */
    public function decode(string $pfxDer, string $password): array
    {
        // Parse PFX outer SEQUENCE
        $pfx = self::parseSequence($pfxDer);
        $offset = 0;

        // Version
        $version = self::parseTlv($pfx, $offset);
        $versionInt = self::decodeInteger($version['value']);
        if ($versionInt !== 3) {
            throw new RuntimeException("Unsupported PFX version: {$versionInt}");
        }

        // AuthSafe ContentInfo
        $authSafeCI = self::parseTlv($pfx, $offset);
        $authSafeCIDer = $authSafeCI['full'];
        $authSafeCIContent = self::parseSequence($authSafeCI['value']);

        // Parse ContentInfo to get authSafe data
        $ciOffset = 0;
        $contentTypeRaw = self::parseTlv($authSafeCIContent, $ciOffset);
        $contentType = self::decodeOid($contentTypeRaw['value']);

        if ($contentType !== PKCS7::OID_DATA) {
            throw new RuntimeException("AuthSafe must be PKCS#7 data, got: {$contentType}");
        }

        // [0] EXPLICIT content
        $contentWrapped = self::parseTlv($authSafeCIContent, $ciOffset);
        $innerOctet = self::parseTlv($contentWrapped['value'], $dummyOffset = 0);
        $authSafeDer = $innerOctet['value'];

        // MacData (optional but expected)
        $macData = null;
        if ($offset < strlen($pfx)) {
            $macDataRaw = self::parseTlv($pfx, $offset);
            $macData = $this->parseMacData($macDataRaw['value']);
        }

        // Verify MAC
        if ($macData !== null) {
            $this->verifyMac($authSafeDer, $password, $macData);
        }

        // Parse AuthenticatedSafe (SEQUENCE OF ContentInfo)
        $authSafe = self::parseSequence($authSafeDer);
        $safeBags = $this->extractAllSafeBags($authSafe, $password);

        // Extract key and certificates from bags
        return $this->processSafeBags($safeBags);
    }

    /**
     * Parse MacData from its ASN.1 value.
     */
    private function parseMacData(string $macDataValue): array
    {
        $content = self::parseSequence($macDataValue);
        $offset = 0;

        // DigestInfo
        $digestInfoRaw = self::parseTlv($content, $offset);
        $digestInfo = self::parseSequence($digestInfoRaw['value']);
        $diOffset = 0;

        // AlgorithmIdentifier
        $algoIdRaw = self::parseTlv($digestInfo, $diOffset);
        $algoContent = self::parseSequence($algoIdRaw['value']);
        $algoOffset = 0;
        $algoOidRaw = self::parseTlv($algoContent, $algoOffset);
        $hashOid = self::decodeOid($algoOidRaw['value']);
        $hashName = $this->macCalculator->getHashName($hashOid);

        // Digest
        $digestRaw = self::parseTlv($digestInfo, $diOffset);
        $digest = $digestRaw['value'];

        // Salt
        $saltRaw = self::parseTlv($content, $offset);
        $salt = $saltRaw['value'];

        // Iterations (optional, defaults to 1)
        $iterations = 1;
        if ($offset < strlen($content)) {
            $iterRaw = self::parseTlv($content, $offset);
            $iterations = self::decodeInteger($iterRaw['value']);
        }

        return [
            'hashAlgorithm' => $hashName,
            'digest' => $digest,
            'salt' => $salt,
            'iterations' => $iterations,
        ];
    }

    /**
     * Verify the PKCS#12 MAC.
     */
    private function verifyMac(string $authSafeDer, string $password, array $macData): void
    {
        $computed = $this->macCalculator->compute(
            $authSafeDer,
            $password,
            $macData['salt'],
            $macData['iterations'],
            $macData['hashAlgorithm'],
        );

        if (!hash_equals($macData['digest'], $computed)) {
            throw new RuntimeException(
                'PKCS#12 MAC verification failed. The password may be incorrect or the file is corrupted.'
            );
        }
    }

    /**
     * Extract all SafeBags from AuthenticatedSafe content.
     */
    private function extractAllSafeBags(string $authSafeContent, string $password): array
    {
        $bags = [];
        $offset = 0;

        while ($offset < strlen($authSafeContent)) {
            $contentInfo = self::parseTlv($authSafeContent, $offset);
            $ciBags = $this->extractBagsFromContentInfo($contentInfo['value'], $password);
            $bags = array_merge($bags, $ciBags);
        }

        return $bags;
    }

    /**
     * Extract SafeBags from a single ContentInfo.
     */
    private function extractBagsFromContentInfo(string $contentInfoValue, string $password): array
    {
        $ciContent = self::parseSequence($contentInfoValue);
        $ciOffset = 0;

        $contentTypeRaw = self::parseTlv($ciContent, $ciOffset);
        $contentType = self::decodeOid($contentTypeRaw['value']);

        if ($ciOffset >= strlen($ciContent)) {
            return [];
        }

        $contentWrapped = self::parseTlv($ciContent, $ciOffset);
        $content = $contentWrapped['value'];

        if ($contentType === PKCS7::OID_DATA) {
            // Plain data: unwrap OCTET STRING
            $innerOffset = 0;
            $octet = self::parseTlv($content, $innerOffset);
            return $this->parseSafeContents($octet['value']);
        }

        if ($contentType === PKCS7::OID_ENCRYPTED_DATA) {
            // Encrypted data
            return $this->decryptAndParseSafeContents($content, $password);
        }

        throw new RuntimeException("Unsupported ContentInfo type: {$contentType}");
    }

    /**
     * Decrypt PKCS#7 EncryptedData and parse SafeContents.
     */
    private function decryptAndParseSafeContents(string $encDataValue, string $password): array
    {
        // Parse EncryptedData
        $edContent = self::parseSequence($encDataValue);
        $edOffset = 0;

        // version
        $versionRaw = self::parseTlv($edContent, $edOffset);

        // EncryptedContentInfo
        $eciRaw = self::parseTlv($edContent, $edOffset);
        $eciContent = self::parseSequence($eciRaw['value']);
        $eciOffset = 0;

        // contentType
        $eciTypeRaw = self::parseTlv($eciContent, $eciOffset);

        // contentEncryptionAlgorithm
        $algoRaw = self::parseTlv($eciContent, $eciOffset);
        $encAlgo = $this->parseEncryptionAlgorithm($algoRaw['value']);

        // encryptedContent [0] IMPLICIT
        $encContentRaw = self::parseTlv($eciContent, $eciOffset);
        $encryptedBytes = $encContentRaw['value'];

        // Decrypt
        $decrypted = $this->decryptContent($encryptedBytes, $password, $encAlgo);

        return $this->parseSafeContents($decrypted);
    }

    /**
     * Parse encryption algorithm and return parameters.
     */
    private function parseEncryptionAlgorithm(string $algoIdValue): array
    {
        $content = self::parseSequence($algoIdValue);
        $offset = 0;

        $oidRaw = self::parseTlv($content, $offset);
        $oid = self::decodeOid($oidRaw['value']);

        $params = '';
        if ($offset < strlen($content)) {
            $paramsRaw = self::parseTlv($content, $offset);
            $params = $paramsRaw['value'];
            $paramsFull = $paramsRaw['full'];
        }

        if ($oid === PKCS7::OID_PBE_SHA1_3DES || $oid === PKCS7::OID_PBE_SHA1_RC2_40) {
            // Legacy PBE
            $pbeParams = self::parseSequence($params);
            $pOffset = 0;
            $saltRaw = self::parseTlv($pbeParams, $pOffset);
            $iterRaw = self::parseTlv($pbeParams, $pOffset);

            return [
                'type' => 'legacy',
                'oid' => $oid,
                'salt' => $saltRaw['value'],
                'iterations' => self::decodeInteger($iterRaw['value']),
            ];
        }

        if ($oid === PKCS7::OID_PBES2) {
            return $this->parsePbes2Params($params);
        }

        throw new RuntimeException("Unsupported encryption algorithm OID: {$oid}");
    }

    /**
     * Parse PBES2 parameters.
     */
    private function parsePbes2Params(string $paramsValue): array
    {
        $content = self::parseSequence($paramsValue);
        $offset = 0;

        // KDF AlgorithmIdentifier
        $kdfAlgoRaw = self::parseTlv($content, $offset);
        $kdfContent = self::parseSequence($kdfAlgoRaw['value']);
        $kdfOffset = 0;
        $kdfOidRaw = self::parseTlv($kdfContent, $kdfOffset);
        $kdfOid = self::decodeOid($kdfOidRaw['value']);

        if ($kdfOid !== PKCS7::OID_PBKDF2) {
            throw new RuntimeException("Unsupported KDF: {$kdfOid}");
        }

        // PBKDF2-params
        $pbkdf2ParamsRaw = self::parseTlv($kdfContent, $kdfOffset);
        $pbkdf2Content = self::parseSequence($pbkdf2ParamsRaw['value']);
        $pbOffset = 0;

        $saltRaw = self::parseTlv($pbkdf2Content, $pbOffset);
        $iterRaw = self::parseTlv($pbkdf2Content, $pbOffset);

        // keyLength (optional)
        $keyLength = null;
        // prf (optional) - default HMAC-SHA1
        $prfHash = 'sha1';

        while ($pbOffset < strlen($pbkdf2Content)) {
            $nextRaw = self::parseTlv($pbkdf2Content, $pbOffset);
            if ($nextRaw['tag'] === 0x02) {
                // INTEGER - keyLength
                $keyLength = self::decodeInteger($nextRaw['value']);
            } elseif ($nextRaw['tag'] === 0x30) {
                // SEQUENCE - prf AlgorithmIdentifier
                $prfContent = self::parseSequence($nextRaw['value']);
                $prfOffset = 0;
                $prfOidRaw = self::parseTlv($prfContent, $prfOffset);
                $prfOid = self::decodeOid($prfOidRaw['value']);
                $prfHash = match ($prfOid) {
                    PKCS7::OID_HMAC_SHA256 => 'sha256',
                    PKCS7::OID_HMAC_SHA1   => 'sha1',
                    default => throw new RuntimeException("Unsupported PRF: {$prfOid}"),
                };
            }
        }

        // Encryption scheme AlgorithmIdentifier
        $encAlgoRaw = self::parseTlv($content, $offset);
        $encContent = self::parseSequence($encAlgoRaw['value']);
        $encOffset = 0;
        $encOidRaw = self::parseTlv($encContent, $encOffset);
        $encOid = self::decodeOid($encOidRaw['value']);

        $algorithm = match ($encOid) {
            PKCS7::OID_AES_256_CBC => 'aes-256-cbc',
            PKCS7::OID_AES_128_CBC => 'aes-128-cbc',
            PKCS7::OID_DES_EDE3_CBC => '3des-cbc',
            default => throw new RuntimeException("Unsupported encryption scheme: {$encOid}"),
        };

        // IV
        $ivRaw = self::parseTlv($encContent, $encOffset);

        return [
            'type' => 'pbes2',
            'salt' => $saltRaw['value'],
            'iterations' => self::decodeInteger($iterRaw['value']),
            'keyLength' => $keyLength,
            'prfHash' => $prfHash,
            'algorithm' => $algorithm,
            'iv' => $ivRaw['value'],
        ];
    }

    /**
     * Decrypt content using parsed algorithm parameters.
     */
    private function decryptContent(string $encrypted, string $password, array $algo): string
    {
        if ($algo['type'] === 'legacy') {
            return $this->pbe->decrypt(
                data: $encrypted,
                password: $password,
                salt: $algo['salt'],
                iv: '', // IV is derived from KDF for legacy
                algorithm: '3des-cbc',
                iterations: $algo['iterations'],
                legacy: true,
            );
        }

        return $this->pbe->decrypt(
            data: $encrypted,
            password: $password,
            salt: $algo['salt'],
            iv: $algo['iv'],
            algorithm: $algo['algorithm'],
            iterations: $algo['iterations'],
            legacy: false,
        );
    }

    /**
     * Parse SafeContents (SEQUENCE OF SafeBag).
     */
    private function parseSafeContents(string $safeContents): array
    {
        $bags = [];
        $content = self::parseSequence($safeContents);
        $offset = 0;

        while ($offset < strlen($content)) {
            $bagRaw = self::parseTlv($content, $offset);
            $bags[] = $this->parseSafeBag($bagRaw['value']);
        }

        return $bags;
    }

    /**
     * Parse a single SafeBag.
     */
    private function parseSafeBag(string $bagValue): array
    {
        $content = self::parseSequence($bagValue);
        $offset = 0;

        // bagId
        $bagIdRaw = self::parseTlv($content, $offset);
        $bagId = self::decodeOid($bagIdRaw['value']);

        // bagValue [0] EXPLICIT
        $bagValueRaw = self::parseTlv($content, $offset);
        $bagContent = $bagValueRaw['value'];

        // bagAttributes (optional)
        $attributes = [];
        if ($offset < strlen($content)) {
            $attrsRaw = self::parseTlv($content, $offset);
            $attributes = $this->parseBagAttributes($attrsRaw['value']);
        }

        return [
            'bagId' => $bagId,
            'bagValue' => $bagContent,
            'attributes' => $attributes,
        ];
    }

    /**
     * Parse bag attributes.
     */
    private function parseBagAttributes(string $attrsValue): array
    {
        $attributes = [];
        $offset = 0;

        while ($offset < strlen($attrsValue)) {
            $attrRaw = self::parseTlv($attrsValue, $offset);
            $attrContent = self::parseSequence($attrRaw['value']);
            $attrOffset = 0;

            $attrIdRaw = self::parseTlv($attrContent, $attrOffset);
            $attrId = self::decodeOid($attrIdRaw['value']);

            $attrValuesRaw = self::parseTlv($attrContent, $attrOffset);
            $attributes[$attrId] = $attrValuesRaw['value'];
        }

        return $attributes;
    }

    /**
     * Process parsed SafeBags to extract key and certificates.
     *
     * @return array{privateKey: string, certificate: string, chain: array<int, string>}
     */
    private function processSafeBags(array $bags): array
    {
        $privateKey = null;
        $certificates = [];
        $localKeyIdToCert = [];

        foreach ($bags as $bag) {
            switch ($bag['bagId']) {
                case SafeBag::BAG_PKCS8_SHROUDED_KEY:
                    // The bagValue is already the decrypted PKCS#8 key
                    // (it was decrypted during extraction from encrypted ContentInfo)
                    // Actually for shroudedKeyBag, the bagValue is EncryptedPrivateKeyInfo
                    // We need the caller to handle this, but since we decrypt at ContentInfo level...
                    // The key DER is the bag value itself
                    $privateKey = $this->derToPem($bag['bagValue'], 'ENCRYPTED PRIVATE KEY');
                    break;

                case SafeBag::BAG_KEY:
                    $privateKey = $this->derToPem($bag['bagValue'], 'PRIVATE KEY');
                    break;

                case SafeBag::BAG_CERT:
                    $certDer = $this->extractCertFromCertBag($bag['bagValue']);
                    $certPem = $this->derToPem($certDer, 'CERTIFICATE');
                    $localKeyId = $bag['attributes'][SafeBag::ATTR_LOCAL_KEY_ID] ?? null;
                    $certificates[] = [
                        'pem' => $certPem,
                        'localKeyId' => $localKeyId,
                    ];
                    break;
            }
        }

        if ($privateKey === null) {
            throw new RuntimeException('No private key found in PKCS#12 bundle');
        }

        // The first certificate with a localKeyId matching the key is the end-entity cert
        // Others are chain certs
        $mainCert = null;
        $chain = [];

        if (count($certificates) === 1) {
            $mainCert = $certificates[0]['pem'];
        } else {
            // Typically the cert with localKeyId is the end-entity cert
            foreach ($certificates as $cert) {
                if ($cert['localKeyId'] !== null && $mainCert === null) {
                    $mainCert = $cert['pem'];
                } else {
                    $chain[] = $cert['pem'];
                }
            }

            // Fallback: first cert is the main cert
            if ($mainCert === null && $certificates !== []) {
                $mainCert = $certificates[0]['pem'];
                $chain = array_map(fn ($c) => $c['pem'], array_slice($certificates, 1));
            }
        }

        return [
            'privateKey' => $privateKey,
            'certificate' => $mainCert ?? '',
            'chain' => $chain,
        ];
    }

    /**
     * Extract the X.509 DER from a CertBag.
     */
    private function extractCertFromCertBag(string $certBagValue): string
    {
        // CertBag ::= SEQUENCE { certId OID, certValue [0] EXPLICIT OCTET STRING }
        $content = self::parseSequence($certBagValue);
        $offset = 0;

        // certId
        $certIdRaw = self::parseTlv($content, $offset);

        // certValue [0] EXPLICIT
        $certValueRaw = self::parseTlv($content, $offset);

        // Inside is OCTET STRING containing the DER cert
        $innerOffset = 0;
        $octetRaw = self::parseTlv($certValueRaw['value'], $innerOffset);

        return $octetRaw['value'];
    }

    /**
     * Convert DER to PEM.
     */
    private function derToPem(string $der, string $label): string
    {
        $b64 = chunk_split(base64_encode($der), 64, "\n");

        return "-----BEGIN {$label}-----\n{$b64}-----END {$label}-----\n";
    }

    // ---- Low-level ASN.1 parsing helpers ----

    /**
     * Parse a SEQUENCE and return its content bytes.
     */
    private static function parseSequence(string $der): string
    {
        $offset = 0;
        $tlv = self::parseTlv($der, $offset);

        if (($tlv['tag'] & 0x1F) !== 0x10 && ($tlv['tag'] & 0x20) === 0) {
            throw new RuntimeException(
                sprintf('Expected SEQUENCE (tag 0x30), got tag 0x%02X', $tlv['tag'])
            );
        }

        return $tlv['value'];
    }

    /**
     * Parse a TLV (tag-length-value) from a byte string at the given offset.
     *
     * @return array{tag: int, value: string, full: string}
     */
    private static function parseTlv(string $data, int &$offset): array
    {
        if ($offset >= strlen($data)) {
            throw new RuntimeException('ASN.1 parse error: unexpected end of data');
        }

        $start = $offset;
        $tag = ord($data[$offset++]);

        // Handle multi-byte tags
        if (($tag & 0x1F) === 0x1F) {
            while ($offset < strlen($data) && (ord($data[$offset]) & 0x80)) {
                $offset++;
            }
            if ($offset < strlen($data)) {
                $offset++;
            }
        }

        // Parse length
        if ($offset >= strlen($data)) {
            throw new RuntimeException('ASN.1 parse error: unexpected end of data in length');
        }

        $lengthByte = ord($data[$offset++]);
        $length = 0;

        if ($lengthByte < 0x80) {
            $length = $lengthByte;
        } elseif ($lengthByte === 0x80) {
            // Indefinite length - not supported in DER
            throw new RuntimeException('ASN.1 indefinite length not supported in DER');
        } else {
            $numBytes = $lengthByte & 0x7F;
            for ($i = 0; $i < $numBytes; $i++) {
                if ($offset >= strlen($data)) {
                    throw new RuntimeException('ASN.1 parse error: unexpected end of data in length bytes');
                }
                $length = ($length << 8) | ord($data[$offset++]);
            }
        }

        if ($offset + $length > strlen($data)) {
            throw new RuntimeException(
                sprintf(
                    'ASN.1 parse error: value length (%d) exceeds data length (%d) at offset %d',
                    $length,
                    strlen($data) - $offset,
                    $offset,
                )
            );
        }

        $value = substr($data, $offset, $length);
        $full = substr($data, $start, $offset - $start + $length);
        $offset += $length;

        return [
            'tag' => $tag,
            'value' => $value,
            'full' => $full,
        ];
    }

    /**
     * Decode an ASN.1 INTEGER value to a PHP integer.
     */
    private static function decodeInteger(string $bytes): int
    {
        $value = 0;
        $negative = (ord($bytes[0]) & 0x80) !== 0;

        foreach (str_split($bytes) as $byte) {
            $value = ($value << 8) | ord($byte);
        }

        if ($negative) {
            $value -= (1 << (8 * strlen($bytes)));
        }

        return $value;
    }

    /**
     * Decode an ASN.1 OBJECT IDENTIFIER.
     */
    private static function decodeOid(string $bytes): string
    {
        if ($bytes === '') {
            return '';
        }

        $first = ord($bytes[0]);
        $components = [
            (int) floor($first / 40),
            $first % 40,
        ];

        $value = 0;
        for ($i = 1; $i < strlen($bytes); $i++) {
            $byte = ord($bytes[$i]);
            $value = ($value << 7) | ($byte & 0x7F);

            if (($byte & 0x80) === 0) {
                $components[] = $value;
                $value = 0;
            }
        }

        return implode('.', $components);
    }
}
