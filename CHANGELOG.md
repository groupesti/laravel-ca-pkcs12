# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-03-29

### Added

- Pure PHP RFC 7292 PKCS#12 (PFX) implementation with no OpenSSL dependency for encoding/decoding.
- `Pkcs12Encoder` for building complete PFX DER structures (PFX version 3, AuthenticatedSafe, SafeBags, MacData).
- `Pkcs12Decoder` for parsing and verifying PFX files with MAC integrity checking.
- `PbeEncryption` service supporting modern PBES2 (PBKDF2-HMAC-SHA256 + AES-256-CBC/AES-128-CBC) and legacy PBE-SHA1-3DES modes.
- `MacCalculator` implementing PKCS#12 KDF per RFC 7292 Appendix B with BMPString password conversion.
- `Pkcs12Manager` service for high-level bundle creation, export, and parsing.
- `Pkcs12Builder` service for programmatic PKCS#12 construction with fluent API.
- `Pkcs12Parser` service for convenient .p12/.pfx file parsing.
- `Pkcs12Bundle` Eloquent model for database-backed bundle metadata.
- ASN.1 map classes: `PFX`, `AuthenticatedSafe`, `SafeContents`, `SafeBag`, `MacData`, `PKCS7`.
- Artisan commands: `ca-pkcs12:create`, `ca-pkcs12:export`, `ca-pkcs12:import`.
- REST API controller with create, show, and export endpoints.
- `Pkcs12Created` and `Pkcs12Exported` events.
- `CaPkcs12` facade for convenient access to the manager.
- Configurable encryption algorithms, MAC algorithms, KDF iterations, and legacy compatibility mode.
- Certificate chain inclusion support with automatic chain building.
- Publishable configuration and migrations.
