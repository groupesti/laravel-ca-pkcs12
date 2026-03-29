<?php

declare(strict_types=1);

namespace CA\Pkcs12\Crypto;

use phpseclib3\Crypt\Hash;
use RuntimeException;

/**
 * Computes PKCS#12 MAC per RFC 7292.
 *
 * Uses the PKCS#12 key derivation function (Appendix B) with ID=3
 * to derive the MAC key, then computes HMAC over the data.
 */
final class MacCalculator
{
    /**
     * PKCS#12 KDF purpose IDs (RFC 7292 Appendix B).
     */
    private const KDF_ID_KEY = 1;
    private const KDF_ID_IV = 2;
    private const KDF_ID_MAC = 3;

    /**
     * Hash algorithm OIDs mapped to names.
     */
    private const HASH_OIDS = [
        'sha1'   => '1.3.14.3.2.26',
        'sha256' => '2.16.840.1.101.3.4.2.1',
        'sha384' => '2.16.840.1.101.3.4.2.2',
        'sha512' => '2.16.840.1.101.3.4.2.3',
    ];

    /**
     * Hash block sizes in bytes (for PKCS#12 KDF "v" parameter).
     */
    private const HASH_BLOCK_SIZES = [
        'sha1'   => 64,
        'sha256' => 64,
        'sha384' => 128,
        'sha512' => 128,
        'md5'    => 64,
    ];

    /**
     * Hash output lengths in bytes (for PKCS#12 KDF "u" parameter).
     */
    private const HASH_OUTPUT_LENGTHS = [
        'sha1'   => 20,
        'sha256' => 32,
        'sha384' => 48,
        'sha512' => 64,
        'md5'    => 16,
    ];

    /**
     * Compute the PKCS#12 MAC digest.
     *
     * @param string $data          The data to MAC (AuthenticatedSafe DER encoding)
     * @param string $password      The password (plaintext)
     * @param string $salt          Random salt bytes
     * @param int    $iterations    KDF iterations
     * @param string $hashAlgorithm Hash algorithm name (sha1, sha256, etc.)
     * @return string The MAC digest bytes
     */
    public function compute(
        string $data,
        string $password,
        string $salt,
        int $iterations,
        string $hashAlgorithm,
    ): string {
        $hashAlgorithm = strtolower($hashAlgorithm);

        $macKeyLength = self::HASH_OUTPUT_LENGTHS[$hashAlgorithm]
            ?? throw new RuntimeException("Unsupported hash algorithm: {$hashAlgorithm}");

        // Derive MAC key using PKCS#12 KDF with ID=3
        $macKey = $this->pkcs12Kdf(
            password: $password,
            salt: $salt,
            iterations: $iterations,
            keyLength: $macKeyLength,
            id: self::KDF_ID_MAC,
            hash: $hashAlgorithm,
        );

        // Compute HMAC
        $hmac = new Hash($hashAlgorithm);
        $hmac->setKey($macKey);

        return $hmac->hash($data);
    }

    /**
     * Get the OID for a hash algorithm name.
     */
    public function getHashOid(string $hashAlgorithm): string
    {
        $hashAlgorithm = strtolower($hashAlgorithm);

        return self::HASH_OIDS[$hashAlgorithm]
            ?? throw new RuntimeException("No OID for hash algorithm: {$hashAlgorithm}");
    }

    /**
     * Get the hash algorithm name from its OID.
     */
    public function getHashName(string $oid): string
    {
        $flipped = array_flip(self::HASH_OIDS);

        return $flipped[$oid]
            ?? throw new RuntimeException("Unknown hash OID: {$oid}");
    }

    /**
     * PKCS#12 Key Derivation Function per RFC 7292 Appendix B.
     *
     * @param string $password   The password (plaintext, will be converted to BMPString)
     * @param string $salt       Salt bytes
     * @param int    $iterations Number of iterations
     * @param int    $keyLength  Desired key length in bytes
     * @param int    $id         Purpose ID (1=key, 2=IV, 3=MAC)
     * @param string $hash       Hash algorithm name
     * @return string Derived key bytes
     */
    public function pkcs12Kdf(
        string $password,
        string $salt,
        int $iterations,
        int $keyLength,
        int $id,
        string $hash,
    ): string {
        $hash = strtolower($hash);

        $v = self::HASH_BLOCK_SIZES[$hash]
            ?? throw new RuntimeException("Unsupported hash for KDF: {$hash}");
        $u = self::HASH_OUTPUT_LENGTHS[$hash]
            ?? throw new RuntimeException("Unsupported hash for KDF: {$hash}");

        // Step 1: Construct D (diversifier) - v bytes of the ID
        $D = str_repeat(chr($id), $v);

        // Step 2: Convert password to BMPString (UTF-16BE) + null terminator
        $bmpPassword = self::toBmpString($password);

        // Step 3: Concatenate salt to be a multiple of v
        $S = '';
        if (strlen($salt) > 0) {
            $sLen = $v * (int) ceil(strlen($salt) / $v);
            $S = '';
            for ($i = 0; $i < $sLen; $i++) {
                $S .= $salt[$i % strlen($salt)];
            }
        }

        // Step 4: Concatenate password to be a multiple of v
        $P = '';
        if (strlen($bmpPassword) > 0) {
            $pLen = $v * (int) ceil(strlen($bmpPassword) / $v);
            $P = '';
            for ($i = 0; $i < $pLen; $i++) {
                $P .= $bmpPassword[$i % strlen($bmpPassword)];
            }
        }

        // Step 5: I = S || P
        $I = $S . $P;

        // Step 6: Iteratively hash to produce enough key material
        $hashObj = new Hash($hash);
        $derivedKey = '';
        $neededBlocks = (int) ceil($keyLength / $u);

        for ($block = 0; $block < $neededBlocks; $block++) {
            // A_1 = Hash(D || I)
            $A = $hashObj->hash($D . $I);

            // A_i = Hash(A_{i-1}) for i = 2..iterations
            for ($iter = 1; $iter < $iterations; $iter++) {
                $A = $hashObj->hash($A);
            }

            $derivedKey .= $A;

            // If we need more blocks, update I
            if ($block + 1 < $neededBlocks) {
                $B = '';
                $bLen = $v;
                for ($j = 0; $j < $bLen; $j++) {
                    $B .= $A[$j % strlen($A)];
                }

                // I = I + B + 1 (treating I as concatenation of v-byte blocks)
                $iLen = strlen($I);
                $newI = '';
                for ($j = 0; $j < $iLen; $j += $v) {
                    $chunk = substr($I, $j, $v);
                    $chunk = self::addBigEndian($chunk, $B);
                    $newI .= $chunk;
                }
                $I = $newI;
            }
        }

        return substr($derivedKey, 0, $keyLength);
    }

    /**
     * Convert a password string to BMPString (UTF-16BE with null terminator).
     *
     * Per PKCS#12 spec, the password is encoded as BMPString (big-endian UTF-16)
     * with a two-byte null terminator appended.
     */
    public static function toBmpString(string $password): string
    {
        if ($password === '') {
            // Empty password => two null bytes (null terminator only)
            return "\x00\x00";
        }

        $bmp = '';
        $chars = mb_str_split($password, 1, 'UTF-8');

        foreach ($chars as $char) {
            $code = mb_ord($char, 'UTF-8');
            $bmp .= pack('n', $code);
        }

        // Append null terminator (two zero bytes)
        $bmp .= "\x00\x00";

        return $bmp;
    }

    /**
     * Add two byte strings as big-endian unsigned integers, carry propagating,
     * result truncated to the length of $a, plus one.
     *
     * This implements: result = (a + b + 1) mod 2^(v*8)
     * Used in PKCS#12 KDF to update I blocks.
     */
    private static function addBigEndian(string $a, string $b): string
    {
        $len = strlen($a);
        $carry = 1; // +1 per the spec
        $result = str_repeat("\x00", $len);

        for ($i = $len - 1; $i >= 0; $i--) {
            $sum = ord($a[$i]) + ord($b[$i]) + $carry;
            $result[$i] = chr($sum & 0xFF);
            $carry = $sum >> 8;
        }

        return $result;
    }
}
