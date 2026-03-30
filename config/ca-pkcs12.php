<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Default Encryption Algorithm
    |--------------------------------------------------------------------------
    |
    | The symmetric encryption algorithm used to protect PKCS#12 contents.
    | Supported: 'aes-256-cbc', 'aes-128-cbc', '3des-cbc'
    |
    */
    'default_encryption' => 'aes-256-cbc',

    /*
    |--------------------------------------------------------------------------
    | Default MAC Algorithm
    |--------------------------------------------------------------------------
    |
    | Hash algorithm used for the PKCS#12 integrity MAC.
    | Supported: 'sha256', 'sha384', 'sha512', 'sha1'
    |
    */
    'default_mac' => 'sha256',

    /*
    |--------------------------------------------------------------------------
    | MAC Iterations
    |--------------------------------------------------------------------------
    |
    | Number of iterations for the PKCS#12 MAC key derivation.
    |
    */
    'mac_iterations' => 2048,

    /*
    |--------------------------------------------------------------------------
    | KDF Iterations
    |--------------------------------------------------------------------------
    |
    | Number of iterations for the password-based key derivation function
    | used when encrypting PKCS#12 bag contents.
    |
    */
    'kdf_iterations' => 2048,

    /*
    |--------------------------------------------------------------------------
    | Include Chain
    |--------------------------------------------------------------------------
    |
    | Whether to include the full certificate chain by default when
    | creating PKCS#12 bundles.
    |
    */
    'include_chain' => true,

    /*
    |--------------------------------------------------------------------------
    | Legacy Compatibility
    |--------------------------------------------------------------------------
    |
    | When true, uses PBE-SHA1-3DES (pbeWithSHAAnd3-KeyTripleDES-CBC)
    | for encryption and SHA-1 for MAC, providing compatibility with
    | legacy systems such as Windows XP and older Java versions.
    |
    */
    'legacy_compatibility' => false,

    /*
    |--------------------------------------------------------------------------
    | Routes
    |--------------------------------------------------------------------------
    */
    'routes' => [
        'enabled' => true,
        'prefix' => 'api/ca/pkcs12',
        'middleware' => ['api'],
    ],

];
