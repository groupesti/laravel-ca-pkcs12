<?php

declare(strict_types=1);

namespace CA\Pkcs12\Asn1;

use CA\Pkcs12\Asn1\Maps\PKCS7;
use CA\Pkcs12\Asn1\Maps\SafeBag;
use CA\Pkcs12\Crypto\MacCalculator;
use CA\Pkcs12\Crypto\PbeEncryption;
use phpseclib3\Crypt\Random;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Element;
use RuntimeException;

/**
 * Encodes a complete PKCS#12 (PFX) DER structure per RFC 7292.
 */
final class Pkcs12Encoder
{
    private const PFX_VERSION = 3;
    private const MAC_SALT_LENGTH = 8;

    public function __construct(
        private readonly PbeEncryption $pbe = new PbeEncryption(),
        private readonly MacCalculator $macCalculator = new MacCalculator(),
    ) {}

    /**
     * Encode a PKCS#12 PFX structure.
     *
     * @param string   $privateKeyDer  PKCS#8 private key in DER format
     * @param string   $certificateDer X.509 certificate in DER format
     * @param string[] $chainCertsDer  Chain certificates in DER format
     * @param string   $password       Password for encryption and MAC
     * @param array    $options        Options: encryption_algorithm, mac_algorithm, mac_iterations,
     *                                          kdf_iterations, friendly_name, legacy
     * @return string PFX in DER format
     */
    public function encode(
        string $privateKeyDer,
        string $certificateDer,
        array $chainCertsDer,
        string $password,
        array $options = [],
    ): string {
        $encAlgo = $options['encryption_algorithm'] ?? 'aes-256-cbc';
        $macAlgo = $options['mac_algorithm'] ?? 'sha256';
        $macIterations = $options['mac_iterations'] ?? 2048;
        $kdfIterations = $options['kdf_iterations'] ?? 2048;
        $friendlyName = $options['friendly_name'] ?? null;
        $legacy = $options['legacy'] ?? false;

        if ($legacy) {
            $encAlgo = '3des-cbc';
            $macAlgo = 'sha1';
        }

        // Generate localKeyId (SHA-1 hash of the certificate DER)
        $localKeyId = sha1($certificateDer, true);

        // Step 1: Build key SafeBag (pkcs8ShroudedKeyBag)
        $keySafeBag = $this->buildShroudedKeyBag(
            $privateKeyDer,
            $password,
            $encAlgo,
            $kdfIterations,
            $legacy,
            $localKeyId,
            $friendlyName,
        );

        // Step 2: Build certificate SafeBag (certBag)
        $certSafeBag = $this->buildCertBag($certificateDer, $localKeyId, $friendlyName);

        // Step 3: Build chain cert SafeBags
        $chainSafeBags = [];
        foreach ($chainCertsDer as $chainCertDer) {
            $chainSafeBags[] = $this->buildCertBag($chainCertDer);
        }

        // Step 4: Build SafeContents
        $keySafeContents = $this->encodeSafeContents([$keySafeBag]);
        $certSafeContents = $this->encodeSafeContents(array_merge([$certSafeBag], $chainSafeBags));

        // Step 5: Wrap key SafeContents in encrypted ContentInfo (PKCS#7 encryptedData)
        $keyContentInfo = $this->buildEncryptedContentInfo(
            $keySafeContents,
            $password,
            $encAlgo,
            $kdfIterations,
            $legacy,
        );

        // Step 6: Wrap cert SafeContents in plain ContentInfo (PKCS#7 data)
        $certContentInfo = $this->buildDataContentInfo($certSafeContents);

        // Step 7: Build AuthenticatedSafe
        $authSafeDer = $this->buildAuthenticatedSafe([$certContentInfo, $keyContentInfo]);

        // Step 8-9: Compute MAC
        $macSalt = Random::string(self::MAC_SALT_LENGTH);
        $macDigest = $this->macCalculator->compute(
            $authSafeDer,
            $password,
            $macSalt,
            $macIterations,
            $macAlgo,
        );
        $macDataDer = $this->buildMacData($macDigest, $macSalt, $macIterations, $macAlgo);

        // Step 10: Wrap authSafe in a ContentInfo
        $authSafeContentInfo = $this->buildDataContentInfo($authSafeDer);

        // Step 11: Assemble PFX
        return $this->buildPfx($authSafeContentInfo, $macDataDer);
    }

    /**
     * Build a pkcs8ShroudedKeyBag SafeBag containing an encrypted PKCS#8 private key.
     */
    private function buildShroudedKeyBag(
        string $privateKeyDer,
        string $password,
        string $algorithm,
        int $iterations,
        bool $legacy,
        string $localKeyId,
        ?string $friendlyName,
    ): string {
        // Encrypt the PKCS#8 private key
        $encResult = $this->pbe->encrypt($privateKeyDer, $password, $algorithm, $iterations, $legacy);

        // Build EncryptedPrivateKeyInfo
        $encryptedPkcs8 = $this->buildEncryptedPrivateKeyInfo(
            $encResult['encrypted'],
            $encResult['salt'],
            $encResult['iv'],
            $algorithm,
            $iterations,
            $legacy,
        );

        // Build bag attributes
        $attributes = $this->buildBagAttributes($localKeyId, $friendlyName);

        // Build SafeBag
        $bagIdDer = ASN1::encodeDER(SafeBag::BAG_PKCS8_SHROUDED_KEY, ['type' => ASN1::TYPE_OBJECT_IDENTIFIER]);
        $bagValueDer = ASN1::encodeDER(
            new Element($encryptedPkcs8),
            ['type' => ASN1::TYPE_ANY, 'constant' => 0, 'explicit' => true],
        );

        return self::sequence($bagIdDer . $bagValueDer . $attributes);
    }

    /**
     * Build EncryptedPrivateKeyInfo ASN.1 structure.
     *
     * EncryptedPrivateKeyInfo ::= SEQUENCE {
     *     encryptionAlgorithm AlgorithmIdentifier,
     *     encryptedData       OCTET STRING
     * }
     */
    private function buildEncryptedPrivateKeyInfo(
        string $encryptedData,
        string $salt,
        string $iv,
        string $algorithm,
        int $iterations,
        bool $legacy,
    ): string {
        $algoId = $legacy
            ? $this->buildLegacyPbeAlgorithmId($salt, $iterations)
            : $this->buildPbes2AlgorithmId($salt, $iv, $algorithm, $iterations);

        $encDataDer = ASN1::encodeDER(
            new Element($encryptedData),
            ['type' => ASN1::TYPE_OCTET_STRING],
        );

        return self::sequence($algoId . $encDataDer);
    }

    /**
     * Build a certBag SafeBag.
     *
     * CertBag ::= SEQUENCE {
     *     certId    OBJECT IDENTIFIER -- x509Certificate (1.2.840.113549.1.9.22.1)
     *     certValue [0] EXPLICIT OCTET STRING -- DER-encoded X.509 cert
     * }
     */
    private function buildCertBag(
        string $certDer,
        ?string $localKeyId = null,
        ?string $friendlyName = null,
    ): string {
        // Build CertBag value
        $certIdDer = ASN1::encodeDER(SafeBag::CERT_X509, ['type' => ASN1::TYPE_OBJECT_IDENTIFIER]);
        $certOctetDer = ASN1::encodeDER(
            new Element($certDer),
            ['type' => ASN1::TYPE_OCTET_STRING],
        );
        // Wrap certValue in [0] EXPLICIT
        $certValueDer = ASN1::encodeDER(
            new Element($certOctetDer),
            ['type' => ASN1::TYPE_ANY, 'constant' => 0, 'explicit' => true],
        );
        $certBagDer = self::sequence($certIdDer . $certValueDer);

        // Build bag attributes
        $attributes = '';
        if ($localKeyId !== null || $friendlyName !== null) {
            $attributes = $this->buildBagAttributes($localKeyId, $friendlyName);
        }

        // Build SafeBag
        $bagIdDer = ASN1::encodeDER(SafeBag::BAG_CERT, ['type' => ASN1::TYPE_OBJECT_IDENTIFIER]);
        $bagValueDer = ASN1::encodeDER(
            new Element($certBagDer),
            ['type' => ASN1::TYPE_ANY, 'constant' => 0, 'explicit' => true],
        );

        return self::sequence($bagIdDer . $bagValueDer . $attributes);
    }

    /**
     * Build bag attributes SET for friendlyName and localKeyId.
     */
    private function buildBagAttributes(?string $localKeyId, ?string $friendlyName): string
    {
        $attrs = [];

        if ($localKeyId !== null) {
            $attrIdDer = ASN1::encodeDER(SafeBag::ATTR_LOCAL_KEY_ID, ['type' => ASN1::TYPE_OBJECT_IDENTIFIER]);
            $valueDer = ASN1::encodeDER(
                new Element($localKeyId),
                ['type' => ASN1::TYPE_OCTET_STRING],
            );
            $valueSetDer = self::set($valueDer);
            $attrs[] = self::sequence($attrIdDer . $valueSetDer);
        }

        if ($friendlyName !== null) {
            $attrIdDer = ASN1::encodeDER(SafeBag::ATTR_FRIENDLY_NAME, ['type' => ASN1::TYPE_OBJECT_IDENTIFIER]);
            $valueDer = ASN1::encodeDER($friendlyName, ['type' => ASN1::TYPE_BMP_STRING]);
            $valueSetDer = self::set($valueDer);
            $attrs[] = self::sequence($attrIdDer . $valueSetDer);
        }

        if ($attrs === []) {
            return '';
        }

        return self::set(implode('', $attrs));
    }

    /**
     * Encode SafeContents as a SEQUENCE OF SafeBag.
     */
    private function encodeSafeContents(array $safeBags): string
    {
        return self::sequence(implode('', $safeBags));
    }

    /**
     * Build a PKCS#7 encryptedData ContentInfo.
     */
    private function buildEncryptedContentInfo(
        string $data,
        string $password,
        string $algorithm,
        int $iterations,
        bool $legacy,
    ): string {
        $encResult = $this->pbe->encrypt($data, $password, $algorithm, $iterations, $legacy);

        $algoId = $legacy
            ? $this->buildLegacyPbeAlgorithmId($encResult['salt'], $iterations)
            : $this->buildPbes2AlgorithmId($encResult['salt'], $encResult['iv'], $algorithm, $iterations);

        // EncryptedContentInfo
        $contentTypeDer = ASN1::encodeDER(PKCS7::OID_DATA, ['type' => ASN1::TYPE_OBJECT_IDENTIFIER]);
        // encryptedContent [0] IMPLICIT OCTET STRING
        $encContentDer = self::contextTag(0, $encResult['encrypted'], implicit: true);

        $encContentInfoDer = self::sequence($contentTypeDer . $algoId . $encContentDer);

        // EncryptedData
        $versionDer = ASN1::encodeDER('0', ['type' => ASN1::TYPE_INTEGER]);
        $encryptedDataDer = self::sequence($versionDer . $encContentInfoDer);

        // ContentInfo wrapping encryptedData
        $outerTypeDer = ASN1::encodeDER(PKCS7::OID_ENCRYPTED_DATA, ['type' => ASN1::TYPE_OBJECT_IDENTIFIER]);
        $outerContentDer = ASN1::encodeDER(
            new Element($encryptedDataDer),
            ['type' => ASN1::TYPE_ANY, 'constant' => 0, 'explicit' => true],
        );

        return self::sequence($outerTypeDer . $outerContentDer);
    }

    /**
     * Build a PKCS#7 data ContentInfo.
     */
    private function buildDataContentInfo(string $data): string
    {
        $typeDer = ASN1::encodeDER(PKCS7::OID_DATA, ['type' => ASN1::TYPE_OBJECT_IDENTIFIER]);
        $octetDer = ASN1::encodeDER(new Element($data), ['type' => ASN1::TYPE_OCTET_STRING]);
        $contentDer = ASN1::encodeDER(
            new Element($octetDer),
            ['type' => ASN1::TYPE_ANY, 'constant' => 0, 'explicit' => true],
        );

        return self::sequence($typeDer . $contentDer);
    }

    /**
     * Build the AuthenticatedSafe SEQUENCE OF ContentInfo.
     */
    private function buildAuthenticatedSafe(array $contentInfos): string
    {
        return self::sequence(implode('', $contentInfos));
    }

    /**
     * Build MacData DER.
     */
    private function buildMacData(
        string $digest,
        string $salt,
        int $iterations,
        string $hashAlgorithm,
    ): string {
        // DigestInfo
        $hashOid = $this->macCalculator->getHashOid($hashAlgorithm);
        $algoOidDer = ASN1::encodeDER($hashOid, ['type' => ASN1::TYPE_OBJECT_IDENTIFIER]);
        $nullDer = ASN1::encodeDER(null, ['type' => ASN1::TYPE_NULL]);
        $algoIdDer = self::sequence($algoOidDer . $nullDer);
        $digestDer = ASN1::encodeDER(new Element($digest), ['type' => ASN1::TYPE_OCTET_STRING]);
        $digestInfoDer = self::sequence($algoIdDer . $digestDer);

        // MacData
        $saltDer = ASN1::encodeDER(new Element($salt), ['type' => ASN1::TYPE_OCTET_STRING]);
        $iterDer = ASN1::encodeDER((string) $iterations, ['type' => ASN1::TYPE_INTEGER]);

        return self::sequence($digestInfoDer . $saltDer . $iterDer);
    }

    /**
     * Assemble the PFX structure.
     */
    private function buildPfx(string $authSafeContentInfo, string $macData): string
    {
        $versionDer = ASN1::encodeDER((string) self::PFX_VERSION, ['type' => ASN1::TYPE_INTEGER]);

        return self::sequence($versionDer . $authSafeContentInfo . $macData);
    }

    /**
     * Build PBES2 AlgorithmIdentifier.
     *
     * PBES2-params ::= SEQUENCE {
     *     keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
     *     encryptionScheme  AlgorithmIdentifier {{PBES2-Encs}}
     * }
     */
    private function buildPbes2AlgorithmId(
        string $salt,
        string $iv,
        string $algorithm,
        int $iterations,
    ): string {
        $keyLength = self::KEY_SIZES[$algorithm]
            ?? throw new RuntimeException("Unsupported: {$algorithm}");

        // PBKDF2-params
        $saltDer = ASN1::encodeDER(new Element($salt), ['type' => ASN1::TYPE_OCTET_STRING]);
        $iterDer = ASN1::encodeDER((string) $iterations, ['type' => ASN1::TYPE_INTEGER]);
        $keyLenDer = ASN1::encodeDER((string) $keyLength, ['type' => ASN1::TYPE_INTEGER]);
        // PRF = HMAC-SHA256
        $prfOidDer = ASN1::encodeDER(PKCS7::OID_HMAC_SHA256, ['type' => ASN1::TYPE_OBJECT_IDENTIFIER]);
        $prfNullDer = ASN1::encodeDER(null, ['type' => ASN1::TYPE_NULL]);
        $prfAlgoIdDer = self::sequence($prfOidDer . $prfNullDer);

        $pbkdf2ParamsDer = self::sequence($saltDer . $iterDer . $keyLenDer . $prfAlgoIdDer);

        $pbkdf2OidDer = ASN1::encodeDER(PKCS7::OID_PBKDF2, ['type' => ASN1::TYPE_OBJECT_IDENTIFIER]);
        $kdfAlgoIdDer = self::sequence($pbkdf2OidDer . $pbkdf2ParamsDer);

        // Encryption scheme
        $encOid = match ($algorithm) {
            'aes-256-cbc' => PKCS7::OID_AES_256_CBC,
            'aes-128-cbc' => PKCS7::OID_AES_128_CBC,
            '3des-cbc'    => PKCS7::OID_DES_EDE3_CBC,
            default       => throw new RuntimeException("Unsupported: {$algorithm}"),
        };
        $encOidDer = ASN1::encodeDER($encOid, ['type' => ASN1::TYPE_OBJECT_IDENTIFIER]);
        $ivDer = ASN1::encodeDER(new Element($iv), ['type' => ASN1::TYPE_OCTET_STRING]);
        $encAlgoIdDer = self::sequence($encOidDer . $ivDer);

        // PBES2-params
        $pbes2ParamsDer = self::sequence($kdfAlgoIdDer . $encAlgoIdDer);

        // Outer AlgorithmIdentifier
        $pbes2OidDer = ASN1::encodeDER(PKCS7::OID_PBES2, ['type' => ASN1::TYPE_OBJECT_IDENTIFIER]);

        return self::sequence($pbes2OidDer . $pbes2ParamsDer);
    }

    /**
     * Build legacy PBE AlgorithmIdentifier (pbeWithSHAAnd3-KeyTripleDES-CBC).
     *
     * PBEParameter ::= SEQUENCE {
     *     salt       OCTET STRING,
     *     iterations INTEGER
     * }
     */
    private function buildLegacyPbeAlgorithmId(string $salt, int $iterations): string
    {
        $oidDer = ASN1::encodeDER(PKCS7::OID_PBE_SHA1_3DES, ['type' => ASN1::TYPE_OBJECT_IDENTIFIER]);
        $saltDer = ASN1::encodeDER(new Element($salt), ['type' => ASN1::TYPE_OCTET_STRING]);
        $iterDer = ASN1::encodeDER((string) $iterations, ['type' => ASN1::TYPE_INTEGER]);
        $paramsDer = self::sequence($saltDer . $iterDer);

        return self::sequence($oidDer . $paramsDer);
    }

    /** Key sizes for PBES2. */
    private const KEY_SIZES = [
        'aes-256-cbc' => 32,
        'aes-128-cbc' => 16,
        '3des-cbc'    => 24,
    ];

    /**
     * Encode a SEQUENCE tag around content.
     */
    private static function sequence(string $content): string
    {
        return self::tag(0x30, $content);
    }

    /**
     * Encode a SET tag around content.
     */
    private static function set(string $content): string
    {
        return self::tag(0x31, $content);
    }

    /**
     * Encode an ASN.1 context-specific tag.
     */
    private static function contextTag(int $number, string $content, bool $implicit = false): string
    {
        $class = 0x80; // Context-specific
        if (!$implicit) {
            $class |= 0x20; // Constructed
        }

        return self::tag($class | $number, $content);
    }

    /**
     * Encode a TLV (tag-length-value).
     */
    private static function tag(int $tag, string $content): string
    {
        $length = strlen($content);

        if ($length < 0x80) {
            return chr($tag) . chr($length) . $content;
        }

        // Long form length
        $lengthBytes = '';
        $tmp = $length;
        while ($tmp > 0) {
            $lengthBytes = chr($tmp & 0xFF) . $lengthBytes;
            $tmp >>= 8;
        }

        return chr($tag) . chr(0x80 | strlen($lengthBytes)) . $lengthBytes . $content;
    }
}
