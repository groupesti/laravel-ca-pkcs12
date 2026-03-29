# Contributing to Laravel CA PKCS#12

Thank you for considering contributing to this package! This document provides guidelines and instructions for contributing.

## Prerequisites

- PHP 8.4+
- Composer 2
- Git
- A working Laravel 12.x or 13.x application (for integration testing)

## Setup

1. Fork and clone the repository:

```bash
git clone git@github.com:your-username/laravel-ca-pkcs12.git
cd laravel-ca-pkcs12
```

2. Install dependencies:

```bash
composer install
```

3. Run the test suite to verify your setup:

```bash
./vendor/bin/pest
```

## Branching Strategy

| Branch | Purpose |
|---|---|
| `main` | Stable, tagged releases |
| `develop` | Work in progress, integration branch |
| `feat/description` | New features |
| `fix/description` | Bug fixes |
| `docs/description` | Documentation only |

Always branch from `develop` and submit PRs back to `develop`.

## Coding Standards

This project follows the Laravel coding style enforced by **Laravel Pint**:

```bash
# Check formatting
./vendor/bin/pint --test

# Fix formatting
./vendor/bin/pint
```

Static analysis is enforced at **PHPStan level 9**:

```bash
./vendor/bin/phpstan analyse
```

### PHP 8.4 Specifics

- Use `readonly` classes and properties for DTOs and value objects.
- Use typed properties, parameters, and return types everywhere.
- Use `final` classes when inheritance is not intended.
- Use named arguments for improved readability in complex method calls.
- Use `match` expressions instead of switch statements.

## Tests

This project uses **Pest 3** for testing:

```bash
# Run all tests
./vendor/bin/pest

# Run with coverage (minimum 80%)
./vendor/bin/pest --coverage --min=80

# Run a specific test file
./vendor/bin/pest tests/Unit/Crypto/PbeEncryptionTest.php
```

All PRs must include tests for new functionality or bug fixes.

## Commit Messages

Follow the **Conventional Commits** specification:

| Prefix | Usage |
|---|---|
| `feat:` | New feature |
| `fix:` | Bug fix |
| `docs:` | Documentation only |
| `chore:` | Build, CI, tooling |
| `refactor:` | Code restructuring without behavior change |
| `test:` | Adding or updating tests |

Examples:

```
feat: add ECDSA key support for PKCS#12 bundles
fix: correct MAC verification for legacy PBE-SHA1-3DES files
docs: update configuration table in README
```

## Pull Request Process

1. Fork the repository and create your branch from `develop`.
2. Write or update tests as needed.
3. Ensure all checks pass: `./vendor/bin/pest`, `./vendor/bin/pint --test`, `./vendor/bin/phpstan analyse`.
4. Update `CHANGELOG.md` under `[Unreleased]`.
5. Update documentation (README, ARCHITECTURE, etc.) if your changes affect public API or structure.
6. Submit a PR to the `develop` branch using the PR template.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.
