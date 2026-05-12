# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

## [Unreleased]

### Changed (BREAKING)

- **Exception hierarchy reworked.** Every exception thrown from a public
  method now implements
  `\ItkDev\OpenIdConnect\Exception\OpenIdConnectExceptionInterface` (new
  marker interface, extends `\Throwable`). Concrete exception classes now
  extend the SPL type that best describes the failure category:
  `\RuntimeException` (network/cache/data — `CacheException`,
  `HttpException`, `JsonException`, `DecodeException`, `JwksException`,
  `CodeException`, `ValidationException`, `ClaimsException`),
  `\LogicException` (programmer/config bug — `BadUrlException`,
  `IllegalSchemeException`, `MissingParameterException`),
  `\InvalidArgumentException` (invalid input — `ConfigurationException`,
  `NegativeCacheDurationException`, `NegativeLeewayException`).
  Consumers catching `ItkOpenIdConnectException` should migrate to
  `OpenIdConnectExceptionInterface`; the abstract class is kept as a
  `@deprecated` alias and still implements the marker, but **concrete
  exceptions no longer extend it**, so existing `catch
  (ItkOpenIdConnectException $e)` blocks will not match anything thrown
  by 5.0+ code.
- `OpenIdConfigurationProvider::__construct` now throws
  `ConfigurationException` (new, `\InvalidArgumentException`-typed)
  instead of a raw `\InvalidArgumentException` when a required option
  is missing. The new type implements the marker; existing
  `catch (\InvalidArgumentException $e)` blocks continue to match.
- `OpenIdConfigurationProvider::getIdToken` narrowed its boundary
  `catch` from `\Exception` to
  `IdentityProviderException|ClientExceptionInterface|\JsonException`.
  Cache failures during `getConfiguration` (called for the token
  endpoint lookup) now propagate as `CacheException` rather than being
  re-wrapped as `CodeException`. Both implement the marker, so a
  consumer catching that is unaffected; a consumer catching only
  `CodeException` will need to widen to the marker for this code path.
- `OpenIdConfigurationProvider` now throws `JwksException` when a JWK
  entry is missing a string `kid` (RFC 7517 §4.5), and the new
  `MetadataException` when an OIDC discovery document is missing a
  required key or has a non-string value at one. Previously the
  non-string value was silently coerced via `(string)` cast, and both
  validation failures bubbled as `CacheException` — semantically
  misleading since the failure is the IdP-returned payload not
  conforming to the OIDC Discovery schema, not the cache layer
  misbehaving. All three throw types implement the marker interface,
  so consumers catching that are unaffected; consumers catching
  `CacheException` specifically for the missing-key case will need to
  widen to the marker or to `MetadataException`.
- `OpenIdConfigurationProvider::getJwtVerificationKeys` now validates
  the JWKS payload at each level before reading values: the top-level
  `keys` property must be an array (`JwksException` otherwise), each
  entry must be a JSON object (`JwksException` otherwise), each entry's
  `kty` must be a string (`JwksException` otherwise), and for RSA keys
  the `e` and `n` modulus/exponent values must both be strings
  (`JwksException` otherwise). Previously these dynamic fields were
  accessed without checking and would either silently produce a
  garbage `Key`, trigger a PHP type error in the base64 decode, or
  fail downstream in `XMLSecurityKey::convertRSA`. The new behaviour
  fails at the malformed-payload boundary with a precise message.
- `OpenIdConfigurationProvider::getIdToken` now throws `CodeException`
  when the token endpoint's JSON response is missing a string
  `id_token`. Previously this would have returned `mixed` from
  `$payload['id_token']` and produced confusing errors at the call
  site.
- Renamed `KeyException` → `JwksException` for symmetry with
  `MetadataException` and clearer scope: the type fires on both
  JWKS-document-level errors (`keys` array missing) and JWK-entry-
  level errors (missing `kid` / `kty` / `e` / `n`), so naming it
  after the document type rather than the individual key is more
  accurate. Consumers catching the marker are unaffected; consumers
  catching the concrete class need to swap the name.
- `OpenIdConfigurationProvider::getJwtVerificationKeys` declares its
  return type as `array<string, Key>` (was just `array`), matching
  the actual shape the method builds. Lets `validateIdToken` pass
  the cached keys to `JWT::decode` without a `mixed` flow at
  `level: max`.
- `OpenIdConfigurationProvider::validateIdToken` narrows its
  `$claims` local via inline `@var \stdClass&object{aud, iss,
  nonce}` so the spec-required claim accesses
  (`$claims->aud` / `$claims->iss` / `$claims->nonce`) type-check at
  `level: max`. No runtime change — these values are guaranteed
  present and string-typed by the OIDC spec and `firebase/php-jwt`
  already enforces JWT validity.

### Documentation

- Added a new "Exception handling" section to `README.md` describing the
  marker interface, the SPL parents of each concrete, the PSR-18
  co-implementation on `HttpException`, and the 4.x → 5.0 catch-block
  migration. Also fixed the `validateIdToken` example to catch the
  marker interface instead of the now-deprecated abstract.
- Added class-level PHPDoc to every concrete exception in
  `src/Exception/` describing what it represents, when it's thrown,
  the rationale for its SPL parent type, and the boundary against
  related concrete types. The audit confirms each of the 15 concretes
  covers a distinct failure category — none would be handled
  identically by a reasonable consumer:
  - `\LogicException` family — `BadUrlException` (URL syntax),
    `IllegalSchemeException` (http without opt-in),
    `MissingParameterException` (caller omitted state/nonce).
  - `\InvalidArgumentException` family — `ConfigurationException`
    (missing required ctor option), `NegativeCacheDurationException`
    (value out of range), `NegativeLeewayException` (value out of range).
  - `\RuntimeException` family — `CacheException` (PSR-6 layer),
    `HttpException` (transport + PSR-18 `ClientExceptionInterface`),
    `JsonException` (parse failure), `DecodeException` (JWK base64
    bytes), `JwksException` (JWKS structure), `CodeException` (token
    exchange), `ValidationException` (JWT signature/decode),
    `ClaimsException` (claim values), `MetadataException` (discovery
    doc structure).

### Added

- `ItkDev\OpenIdConnect\Exception\OpenIdConnectExceptionInterface`
  marker for catching every OIDC failure from this library.
- `ItkDev\OpenIdConnect\Exception\ConfigurationException` for missing
  or invalid constructor options.
- `ItkDev\OpenIdConnect\Exception\MetadataException` (extends
  `\RuntimeException`, implements the marker) for IdP-returned OIDC
  discovery documents that parse as JSON but don't conform to the
  OIDC Discovery spec (missing required key, wrong type at a required
  key). Distinct from `JsonException` (parse failure) and
  `CacheException` (PSR-6 cache layer failure) — different remediation
  paths (retry doesn't help; the IdP needs to fix its payload).
- `tests/Exception/ExceptionHierarchyTest.php` locks the contract:
  every concrete implements the marker, extends the correct SPL parent,
  and is caught by a `catch (OpenIdConnectExceptionInterface $e)`
  block. Failing this test class is the early warning that the public
  contract has drifted.

### Deprecated

- `ItkDev\OpenIdConnect\Exception\ItkOpenIdConnectException` abstract
  class (catch `OpenIdConnectExceptionInterface` instead). Kept through
  5.x; removal scheduled for 6.0.

### Tooling

- Bumped PHPStan from `level: 8` to `level: max` in `phpstan.neon`.
  The preceding PRs in the 5.0 series (constructor option shapes,
  JSON-payload narrowing, claim shape on `validateIdToken`, JWKS
  validation, test-side Mockery / fixture / claim narrowings) cleared
  every max-level error; the bump is the final one-line config
  change that locks in the strictest analysis level for future
  contributions.
- `OpenIdConfigurationProvider::__construct` now declares an
  `array{cacheItemPool?: CacheItemPoolInterface,
  openIDConnectMetadataUrl?: string, cacheDuration?: int, leeway?: int,
  allowHttp?: bool, ...}` PHPDoc shape for the `$options` parameter
  (plus a corresponding shape on `$collaborators` for the `jwt` /
  `httpClient` keys). PHPStan can now narrow each setter argument to
  the expected type instead of seeing `mixed`. Behaviour unchanged —
  removes 4 errors when running PHPStan at `level: max`. Also drops a
  now-redundant `is_int($options['leeway'])` runtime check that
  became a `function.alreadyNarrowedType` tautology once the shape
  was in place (PHP itself enforces the `int` via the `setLeeway`
  signature under `declare(strict_types=1)`).
- Collapsed multi-line `@param` / `@return` descriptions in
  `OpenIdConfigurationProvider` and the test suite onto single
  lines. `phpdoc_align: vertical` (the @Symfony preset default)
  doesn't *create* the wraps — it just aligns whatever multi-line
  structure already exists in the source, so a one-time manual
  flatten gives the cleaner format and Symfony's vertical
  alignment then pads description columns into a tidy table:

      * @param string|null $postLogoutRedirectUri The URL …
      * @param string|null $state                 If a state …
      * @param string|null $idToken               The id token

  Future docblocks added with everything on one line stay that
  way under the same alignment rule.
- PHPStan now scans `tests/` in addition to `src/` at level 8, with
  `reportIgnoresWithoutComments: true` so unexplained
  `@phpstan-ignore` directives fail CI.
- Added `phpstan/phpstan-mockery` to `require-dev` for stubs covering
  Mockery's fluent `shouldReceive(...)->andReturn(...)` API.
- Cleaned the 46 pre-existing level-8 issues in `tests/`: dropped the
  unused nullable from `$this->provider`, narrowed `validateIdToken`
  claim accesses with `object{nonce, aud}` `@var` shapes, replaced
  silent `(string)` coercion of `file_get_contents` / `parse_url`
  failures with `assertNotFalse` / `assertIsString` boundary guards,
  swapped `assertTrue(true)` tautologies for
  `expectNotToPerformAssertions`, and replaced the constant-folded
  `is_subclass_of` marker check with a `ReflectionClass` lookup so
  PHPStan can't fold it into a tautology. `phpstan-baseline.neon`
  consequently shrinks to zero and is deleted.

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

[Unreleased]: https://github.com/itk-dev/openid-connect/compare/4.1.2...HEAD
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
