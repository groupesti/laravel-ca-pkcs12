# Architecture — laravel-ca-pkcs12 (PKCS#12 Bundle Management)

## Overview

`laravel-ca-pkcs12` handles the creation, export, import, and parsing of PKCS#12 (.pfx/.p12) bundles -- the standard container format for packaging a private key with its certificate chain. It implements PKCS#12 encoding and decoding in pure PHP with ASN.1 maps, password-based encryption (PBE), and MAC integrity verification. It depends on `laravel-ca` (core), `laravel-ca-crt` (certificates and chain building), `laravel-ca-key` (key access), and `laravel-ca-log` (structured audit logging via CaLog facade).

## Directory Structure

```
src/
├── Pkcs12ServiceProvider.php          # Registers crypto, ASN.1, parser, builder, manager
├── Asn1/
│   ├── Pkcs12Encoder.php             # Encodes PKCS#12 PFX structures to DER
│   ├── Pkcs12Decoder.php             # Decodes DER-encoded PKCS#12 bundles
│   └── Maps/
│       ├── PFX.php                    # ASN.1 map for the top-level PFX structure
│       ├── PKCS7.php                  # ASN.1 map for PKCS#7 ContentInfo wrapper
│       ├── AuthenticatedSafe.php      # ASN.1 map for AuthenticatedSafe sequence
│       ├── SafeBag.php                # ASN.1 map for SafeBag (key or cert container)
│       ├── SafeContents.php           # ASN.1 map for SafeContents sequence
│       └── MacData.php               # ASN.1 map for MAC integrity data
├── Console/
│   └── Commands/
│       ├── Pkcs12CreateCommand.php    # Create a PKCS#12 bundle (ca-pkcs12:create)
│       ├── Pkcs12ExportCommand.php    # Export a bundle to file (ca-pkcs12:export)
│       └── Pkcs12ImportCommand.php    # Import a .pfx/.p12 file (ca-pkcs12:import)
├── Contracts/
│   ├── Pkcs12BuilderInterface.php     # Contract for fluent PKCS#12 construction
│   └── Pkcs12ManagerInterface.php     # Contract for PKCS#12 lifecycle management
├── Crypto/
│   ├── MacCalculator.php              # HMAC computation for PKCS#12 integrity verification
│   └── PbeEncryption.php             # Password-Based Encryption (PBE) for SafeBag contents
├── Events/
│   ├── Pkcs12Created.php              # Fired when a bundle is created
│   └── Pkcs12Exported.php            # Fired when a bundle is exported
├── Facades/
│   └── CaPkcs12.php                   # Facade resolving Pkcs12ManagerInterface
├── Http/
│   ├── Controllers/
│   │   └── Pkcs12Controller.php       # REST API for PKCS#12 operations
│   ├── Requests/
│   │   └── CreatePkcs12Request.php    # Validation for bundle creation
│   └── Resources/
│       └── Pkcs12Resource.php         # JSON API resource for bundle metadata
├── Models/
│   └── Pkcs12Bundle.php              # Eloquent model storing bundle metadata
└── Services/
    ├── Pkcs12Builder.php              # Fluent builder: set key, cert, chain, password, then build
    ├── Pkcs12Manager.php              # Full lifecycle: create, import, export bundles
    └── Pkcs12Parser.php               # Parses .pfx/.p12 files into key, cert, and chain components
```

## Service Provider

`Pkcs12ServiceProvider` registers the following:

| Category | Details |
|---|---|
| **Config** | Merges `config/ca-pkcs12.php`; publishes under tag `ca-pkcs12-config` |
| **Singletons** | `MacCalculator`, `PbeEncryption`, `Pkcs12Encoder`, `Pkcs12Decoder`, `Pkcs12Parser`, `Pkcs12ManagerInterface` (resolved to `Pkcs12Manager`) |
| **Bindings** | `Pkcs12BuilderInterface` (non-singleton, fresh per resolve) |
| **Alias** | `ca-pkcs12` points to `Pkcs12ManagerInterface` |
| **Migrations** | `ca_pkcs12_bundles` table |
| **Commands** | `ca-pkcs12:create`, `ca-pkcs12:export`, `ca-pkcs12:import` |
| **Routes** | API routes under configurable prefix (default `api/ca/pkcs12`) |

## Key Classes

**Pkcs12Manager** -- Orchestrates PKCS#12 bundle creation and import. For creation, it resolves the certificate, builds the chain via `ChainBuilder` (from `laravel-ca-crt`), retrieves the private key, and delegates to `Pkcs12Encoder` to produce the DER-encoded bundle. For import, it delegates to `Pkcs12Decoder` to extract components, then stores them appropriately.

**Pkcs12Encoder** -- Builds DER-encoded PKCS#12 bundles according to the PFX structure defined in RFC 7292. Wraps the private key and certificates in SafeBag structures, encrypts them with password-based encryption, computes the MAC for integrity, and assembles the final PFX.

**Pkcs12Decoder** -- Parses DER-encoded PKCS#12 data. Verifies MAC integrity, decrypts SafeBag contents using the password, and extracts the private key, certificate, and chain certificates.

**PbeEncryption** -- Implements PKCS#12 Password-Based Encryption schemes. Derives encryption keys from the password using the PKCS#12 key derivation function, then encrypts/decrypts SafeBag content using the derived key.

**MacCalculator** -- Computes and verifies the HMAC-based integrity check embedded in PKCS#12 bundles. Uses PKCS#12 key derivation to produce the MAC key from the bundle password.

## Design Decisions

- **Pure PHP PKCS#12**: The entire PKCS#12 encoding/decoding is implemented in PHP using phpseclib's ASN.1 primitives. This avoids dependency on `openssl_pkcs12_*` functions which have limited control over encryption algorithms and compatibility options.

- **Layered crypto architecture**: `MacCalculator` and `PbeEncryption` are separate singletons. `PbeEncryption` depends on `MacCalculator` for key derivation, and both `Pkcs12Encoder` and `Pkcs12Decoder` depend on both. This separation allows independent testing and potential replacement.

- **Builder is non-singleton**: `Pkcs12Builder` uses `$this->app->bind()` to ensure each resolution starts with a clean state, preventing bundle data from leaking between requests.

## PHP 8.4 Features Used

- **Named arguments**: Used extensively in constructor injection (`pbe:`, `macCalculator:`, `keyManager:`).
- **`readonly` constructor promotion**: Used in all service classes.
- **Strict types**: Every file declares `strict_types=1`.

## Extension Points

- **Pkcs12BuilderInterface**: Replace the builder to customize PKCS#12 assembly (e.g., different encryption algorithms).
- **Pkcs12ManagerInterface**: Bind a custom manager for alternative bundle workflows.
- **Events**: Listen to `Pkcs12Created`, `Pkcs12Exported` for audit and access logging.
- **Logging**: All service operations are logged via `CaLog` facade (`CA\Log\Facades\CaLog`). Successful operations emit info-level logs; failures emit critical-level logs before re-throwing. Operations tracked: `pkcs12_create`, `pkcs12_export`, `pkcs12_build`, `pkcs12_parse`.
- **Config**: Customize route prefix, middleware, and default encryption parameters via `config/ca-pkcs12.php`.
