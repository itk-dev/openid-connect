# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

## [Unreleased]

### Changed

- Strengthened constructor tests guided by mutation testing: the `jwt`
  collaborator is asserted to become the request factory, and `0` is
  asserted to be an accepted boundary value for `cacheDuration` and
  `leeway`

## [5.0.0] - 2026-06-02

Reworked exception hierarchy and tightened IdP-payload validations. The runtime
behaviour is unchanged for spec-compliant IdPs — see [UPGRADE-5.0.md](UPGRADE-5.0.md)
for the consumer migration guide.

### Changed (BREAKING)

- Reworked exception hierarchy around the new
  `OpenIdConnectExceptionInterface` marker. Concrete exception classes now extend the
  SPL type that best describes the failure category (`\RuntimeException`,
  `\LogicException`, `\InvalidArgumentException`) instead of the abstract
  `ItkOpenIdConnectException`. Existing `catch (ItkOpenIdConnectException $e)` blocks
  will not match anything thrown by 5.0+ code — catch the marker, or scope to a more
  specific concrete / SPL parent
- Renamed `KeyException` → `JwksException` for symmetry with the new
  `MetadataException` and to better describe its scope (the type fires for both
  JWKS-document-level and JWK-entry-level errors)
- `OpenIdConfigurationProvider::__construct` now throws the typed
  `ConfigurationException` (still extending `\InvalidArgumentException`) instead of
  a raw `\InvalidArgumentException` for missing required options
- New typed throws replace 4.x silent coercions: malformed JWKS payload
  (missing `keys` array, non-object JWK entry, missing/non-string `kid` /
  `kty` / RSA `e` / `n`, unsupported `kty`) → `JwksException`; malformed
  OIDC discovery document → `MetadataException`; token endpoint response
  missing string `id_token` → `CodeException`
- `OpenIdConfigurationProvider::getIdToken` narrowed its boundary `catch` from
  `\Exception` to the three actually-thrown families
  (`IdentityProviderException|ClientExceptionInterface|\JsonException`).
  Exceptions from the upstream `getConfiguration('token_endpoint')` call
  (`CacheException`, `HttpException`, `MetadataException`, library
  `JsonException`) now propagate as themselves rather than being re-wrapped
  as `CodeException`

### Added

- Marker interface `OpenIdConnectExceptionInterface` (extends `\Throwable`)
- Concrete exceptions `ConfigurationException` and `MetadataException`
- `tests/Exception/ExceptionHierarchyTest.php` locks the contract: every concrete
  implements the marker, extends the correct SPL parent, and is caught by a single
  `catch (OpenIdConnectExceptionInterface $e)` block

### Deprecated

- Abstract `ItkOpenIdConnectException` — catch `OpenIdConnectExceptionInterface`
  instead. Kept through 5.x as a documented alias that still implements the marker;
  removal scheduled for 6.0

### Documentation

- Added an "Exception handling" section to `README.md` covering the marker
  interface, SPL parents, PSR-18 co-implementation on `HttpException`, and the
  4.x → 5.0 catch-block migration
- Class-level PHPDoc on every concrete exception describing its trigger sites and
  the boundary against related types

### Tooling

- PHPStan bumped to `level: max` (was 8). Scans `src/` + `tests/`
- `reportIgnoresWithoutComments: true` so unexplained `@phpstan-ignore` directives
  fail CI
- Added `phpstan/phpstan-mockery` to `require-dev` for stubs covering Mockery's
  fluent `shouldReceive(...)->andReturn(...)` API

## [4.1.2] - 2026-05-11

- Chained `previous` consistently in `OpenIdConfigurationProvider` catch
  blocks (`validateIdToken`, `getJwtVerificationKeys`, `fetchJsonResource`,
  `getConfiguration`) so consumers can walk back to the underlying
  Guzzle/firebase/PSR exception via `getPrevious()`
- Tightened `@throws` phpdoc on public methods (`validateIdToken`,
  `getIdToken`, `getBaseAuthorizationUrl`) to enumerate the actual
  transitive exceptions instead of declaring only the parent type. Removed
  the inaccurate `ClientExceptionInterface` declaration on `getIdToken`
  (the catch-all wraps it as `CodeException` with the original chained)
- Documented HTTP timeout/proxy/verify configuration via constructor `$options`
  (capability already provided by league/oauth2-client; no code change)
- Bumped `actions/checkout` from v5 to v6 in all CI workflows
- Added `ci` profile to docker-compose matrix services to avoid starting them during local development
- Fixed `test:coverage` task to run via docker-compose with `XDEBUG_MODE=coverage`
- Fixed `test:run` to remove stale `composer.lock` before `composer update`
- Fixed `test:matrix:reset` to use `--profile ci` flag
- Removed unused `.markdownlint.json`

## [4.1.1] - 2026-05-07

### Security

- Bumped `robrichards/xmlseclibs` constraint to `^3.1.5` to address
  [CVE-2026-32313](https://github.com/advisories/GHSA-4v26-v6cg-g6f9)
  (high severity — missing AES-GCM authentication tag validation on
  encrypted nodes). The library uses xmlseclibs only for RSA key
  construction (`XMLSecurityKey::convertRSA`), but consumers are
  protected against the encrypted-node decryption issue regardless.

## [4.1.0] - 2026-03-20

- Achieved 100% test coverage (methods and lines)
- Fixed JWKS verification keys not being persisted to cache
- Documented JWT::$leeway static property limitation and exp claim validation

## [4.0.3] - 2026-03-09

- Upgraded PHPUnit from 11 to 12, Updated `phpunit.xml.dist` schema to 12.5
- Upgraded `firebase/php-jwt` to 7.* to fix security vulnerability.

## [4.0.2] - 2025-10-06

- Handled an array of audiences on ID token.

## [4.0.1] - 2025-01-13

- Fix create release action

## [4.0.0] - 2025-01-11

- Removed support for PHP 8.1 and 8.2 (BC)
- Changed from Psalm to PHPStan
- Upgrade to PHPUnit 11
- Add Github action to auto create releases

## [3.2.1] - 2023-09-18

### Fixed

- Fixed "Return value of JWT::getKey() must be an instance of Firebase\JWT\Key" error

## [3.2.0] - 2023-09-11

### Changed

- Updated `firebase/php-jwt` to 6.8
- Updated `vimeo/psalm` to 5.x
- Update to latest github actions

### Added

- Add PHP 8.2 to list of tested versions
- Add changelog check to github actions

## [3.1.0] - 2023-07-03

### Added

- Added support for [Authorization Code
  Flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow)

## [3.0.1] - 2022-10-07

### Fixed

- Add missing direct dependency on `psr/http-client`

## [3.0.0] - 2021-12-08

### Changed

- Dropped support for PHP 7.3
- Changed leeway to be a config option for providers [BC]

### Fixed

- Fixed coverage for test suite

## [2.3.0] - 2021-12-08

### Added

- Include metadata url in cache key (to support multiple providers).

## [2.2.0] - 2021-09-28

### Added

- Function to get the logout / end session url from the config metadata

### Changed

- Updated CHANGELOG
- Added badges to Readme

### Fixed

- Update validation example in README
- Fixed composer scripts

## [2.1.0] - 2021-06-14

### Added

- Leeway option when validating id token

## [2.0.0] - 2021-06-04

### Security

- Fixed security issue, where token was not validated against the signing keys
-

### Added

- Test suite
- Psalm setup for static analysis
- Code formatting

### Changed

- Switched to PSR-6 caching

## [1.0.0] - 2021-03-12

### Added

- README
- LICENSE
- OpenId-Connect: Added OpenIdConfigurationProvider
- PHP-CS-Fixer
- This CHANGELOG file to hopefully serve as an evolving example of a
  standardized open source project CHANGELOG.

[Unreleased]: https://github.com/itk-dev/openid-connect/compare/5.0.0...HEAD
[5.0.0]: https://github.com/itk-dev/openid-connect/compare/4.1.2...5.0.0
[4.1.2]: https://github.com/itk-dev/openid-connect/compare/4.1.1...4.1.2
[4.1.1]: https://github.com/itk-dev/openid-connect/compare/4.1.0...4.1.1
[4.1.0]: https://github.com/itk-dev/openid-connect/compare/4.0.3...4.1.0
[4.0.3]: https://github.com/itk-dev/openid-connect/compare/4.0.2...4.0.3
[4.0.2]: https://github.com/itk-dev/openid-connect/compare/4.0.1...4.0.2
[4.0.1]: https://github.com/itk-dev/openid-connect/compare/4.0.0...4.0.1
[4.0.0]: https://github.com/itk-dev/openid-connect/compare/3.2.1...4.0.0
[3.2.1]: https://github.com/itk-dev/openid-connect/compare/3.2.0...3.2.1
[3.2.0]: https://github.com/itk-dev/openid-connect/compare/3.1.0...3.2.0
[3.1.0]: https://github.com/itk-dev/openid-connect/compare/3.0.0...3.1.0
[3.0.0]: https://github.com/itk-dev/openid-connect/compare/2.3.0...3.0.0
[2.3.0]: https://github.com/itk-dev/openid-connect/compare/2.2.0...2.3.0
[2.2.0]: https://github.com/itk-dev/openid-connect/compare/2.1.0...2.2.0
[2.1.0]: https://github.com/itk-dev/openid-connect/compare/2.0.0...2.1.0
[2.0.0]: https://github.com/itk-dev/openid-connect/compare/1.0.0...2.0.0
[1.0.0]: https://github.com/itk-dev/openid-connect/releases/tag/1.0.0
