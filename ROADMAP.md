# Roadmap

## v0.1.0 — Initial Release (done)

- [x] Pure PHP PKCS#12 encoder/decoder (RFC 7292)
- [x] PBES2 encryption (PBKDF2 + AES-256-CBC / AES-128-CBC)
- [x] Legacy PBE-SHA1-3DES compatibility mode
- [x] MAC integrity verification with configurable algorithms
- [x] Pkcs12Manager high-level service (create, export, parse)
- [x] Pkcs12Builder fluent API
- [x] Artisan commands (create, export, import)
- [x] REST API endpoints
- [x] Eloquent model for bundle metadata
- [x] Certificate chain inclusion

## v0.2.0 — Planned

- [ ] PKCS#12 password change without full re-encoding
- [ ] Support for CRL bags and secret bags
- [ ] Batch export of multiple bundles
- [ ] Configurable friendly name templates

## v1.0.0 — Stable Release

- [ ] Full test coverage (90%+)
- [ ] Performance benchmarks for large chain certificates
- [ ] Comprehensive API documentation

## Ideas / Backlog

- PKCS#12 v2 (PBES2 with Argon2) when RFC support matures
- Hardware Security Module (HSM) integration for key wrapping
- WebCrypto-compatible export format
