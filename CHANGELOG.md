# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

## [Unreleased]

### Removed

- Dependency on `robrichards/xmlseclibs`. JWKS entries are converted to
  verification keys by `firebase/php-jwt`'s own `JWK::parseKey()`, which this
  library already depended on, instead of `XMLSecurityKey::convertRSA()`. Also
  drops the `phpseclib/phpseclib` subtree that `xmlseclibs` 4.0 brought with it.
  The strict JWKS validation from 5.0.0 is unchanged and still runs ahead of
  `parseKey()`, which on its own accepts a non-string, empty or undecodable
  exponent, coerces a non-string `kid`, and raises a bare `\TypeError` on a
  non-object entry

### Added

- Mutation testing with [Infection](https://infection.github.io/)
  (`task test:mutation`), run in CI and reported to the Stryker dashboard
  (mutation score badge in README)
- `phpstan-lowest` CI job and the matching `task analyze:php:lowest`, analysing
  the declared dependency floor with current dev tooling. Only the packages
  `require` names are lowered, so findings are about the runtime dependencies
  rather than a downgraded PHPUnit

### Changed

- `allowHttp` now governs every URL the client talks to, not just
  `openIDConnectMetadataUrl`. The `authorization_endpoint`, `token_endpoint`,
  `userinfo_endpoint`, `end_session_endpoint` and `jwks_uri` read from the IdP's
  discovery document are validated against the same scheme policy and raise
  `IllegalSchemeException` when they announce plain http with `allowHttp` at its
  default `false` (a malformed endpoint URL raises `BadUrlException`).
  Previously these were used verbatim, so a tampered or misconfigured discovery
  document could get the client secret posted in plaintext during the code
  exchange. **Deployments talking to an IdP that announces plain-http endpoints
  — a local Keycloak without TLS — must now set `allowHttp`**, which is the
  documented switch for exactly that situation. Scheme comparison is
  case-insensitive per RFC 3986 §3.1, so `HTTPS://` is accepted where it was
  previously rejected
- Strengthened tests guided by mutation testing; mutation score raised to
  100% with a CI threshold of 100 (`minMsi` / `minCoveredMsi` in
  `infection.json5`). The four provably equivalent mutants that remain are
  excluded per mutator with the reason stated, so the threshold is binding: a
  newly escaped mutant fails the build rather than being absorbed by headroom,
  and pull requests stay free of `--logger-github` annotations unless they
  genuinely regress the score
- The write to `firebase/php-jwt`'s process-global `JWT::$leeway` is contained in
  a single private `decodeWithLeeway()` method, which does nothing but set the
  static and decode. Behaviour is unchanged; the point is that the constraint
  — nothing that could suspend may come between the write and the decode — now
  has one home and a stated rationale instead of being an ordering that happened
  to hold. Under PHP-FPM this is a formality, but it is what a fibre-based or
  worker runtime would depend on
- The previous `JWT::$leeway` value is restored after each decode. Under PHP-FPM
  the mutated static died with the request; in a worker process it persisted for
  the life of the process and silently applied to any other `firebase/php-jwt`
  consumer that never set its own leeway. Writing a process-global is
  unavoidable given the upstream API, but leaving it written is not
- The discovery document and the JWKS are capped at 1 MiB each, raising
  `HttpException` when a response exceeds it. Both are a few kilobytes in
  practice, so a hostile or misconfigured endpoint could previously hand over an
  unbounded body to decode and cache. The declared body size is checked first
  where the response reports one, and the retrieved content unconditionally,
  since a chunked response reports no size. The cap bounds what gets decoded and
  cached rather than peak memory — Guzzle has already buffered the body by the
  time this library sees it
- `validateIdToken()` now requires the `exp` and `iat` claims, both REQUIRED by
  OIDC Core §2, and raises `ClaimsException` when either is absent or
  non-numeric. `firebase/php-jwt` validates `exp` only when it is present, so a
  token omitting it never expired. Forged tokens already died at the signature
  check, so this needs a misbehaving IdP to matter — but **an IdP that issues ID
  tokens without `exp` or `iat` will now be rejected**
- `validateIdToken()` compares the nonce with `hash_equals()` rather than `!==`.
  The nonce is the one claim checked against a value the caller holds, so a
  timing signal there would leak that secret rather than a public identifier
- `validateIdToken()` compares the audience strictly. PHP's loose comparison
  treats numeric strings as equal by value, so an IdP announcing an audience of
  `"1e2"` previously satisfied a client id of `"100"`. Audience entries that are
  not strings are ignored, since they cannot match a string client id
- `validateIdToken()` requires `iss` and `nonce` to be non-empty strings, raising
  `ClaimsException` otherwise. Both were interpolated into exception messages
  unchecked, so a signed token carrying an array in either claim turned a claims
  mismatch into an `\Error` that did not implement
  `OpenIdConnectExceptionInterface`
- The JWKS cache now holds the discovery-fetched JWKS document rather than the
  `Key` objects built from it, under a new cache key (`…||jwks-document`).
  `JWK::parseKey()` returns keys wrapping an `OpenSSLAsymmetricKey`, which PHP
  refuses to serialize, so they cannot go into a PSR-6 pool; the document is
  cached instead and parsed on each call, which costs microseconds and keeps the
  network fetch cached exactly as before. Entries written by 5.0 under the old
  `…||jwks` key are left untouched rather than misread, and expire on their own
- PHPStan analyses the whole PHP range `composer.json` declares (`phpVersion`
  8.3–8.5 in `phpstan.neon`) rather than whichever version the job happens to
  run on, and the main job runs on PHP 8.5 so it resolves the newest installable
  dependency set. Previously analysing on 8.3 said nothing about 8.5
- Raised the `league/oauth2-client` floor to `^2.8.1` (was `^2.6`). PKCE support
  arrived in 2.7.0, and 2.8.1 raises league's own Guzzle constraint to
  `^6.5.8 || ^7.4.5` for the advisories affecting earlier releases
- Raised `robrichards/xmlseclibs` to `^4.0` (was `^3.1.5`). 4.0 requires
  `php >= 8.0`, which this library's `php ^8.3` satisfies, and replaces its
  `ext-openssl` requirement with `phpseclib/phpseclib ^3.0`.
  `XMLSecurityKey::convertRSA()` — the only API used here — is unchanged
- Bumped `infection/infection` to `^0.35.2` (was `^0.33.2`), so the 100
  threshold is verified against the current mutator set rather than one two
  minors behind. The newer release generates the same mutants and needs no
  config changes
- `getIdToken()` no longer lists `IdentityProviderException` among the
  exceptions it wraps as `CodeException`. The method issues the token request
  directly rather than through league's `getParsedResponse()`, so
  `checkResponse()` — the only source of that exception — is never on this path.
  No change in observable behaviour; the 5.0.0 note naming it was inaccurate
- Dropped the redundant `'scope' => 'openid'` default from
  `getAuthorizationUrl()`. league's `getAuthorizationParameters()` already
  backfills the scope from `getDefaultScopes()`, which returns the same value
- Test fixtures and README examples use RFC 2606 reserved domains
  (`provider.example.org` for IdP-side URLs, `app.example.org` for
  application-side URLs) instead of invented registrable domains

### Deprecated

- The `response_type` default of `id_token` in `getAuthorizationUrl()`, together
  with the `response_mode` default of `query`. That pair is the OIDC implicit
  flow with the ID token delivered in the query string: OIDC Core §3.2.2.5
  returns implicit-flow parameters in the fragment, so the `query` mode relies on
  a provider extension to be readable server-side, and it puts a credential where
  access logs and browser history can keep it. Pass
  `'response_type' => 'code'` and exchange the code with `getIdToken()`. **The
  default becomes `code` in 6.0**, so passing it explicitly now is
  forward-compatible. No runtime deprecation notice is emitted, since the noise
  would fall on consumers who cannot silence it except by making this change

### Documentation

- Named the storage contract for `state` and `nonce`: the caller persists both
  and compares against its own copy. `AbstractProvider` keeps the state on the
  provider object, so the inherited `getState()` returns it — but on an instance
  shared between requests (a long-running worker, or a container that memoizes
  the service) that property holds whichever request wrote it last, which may
  belong to a different user. `getAuthorizationUrl()` writes it whether or not
  `generateState()` is used, so the guidance is to never read it back rather
  than to avoid one method. Documented in `README.md` and on both generator
  methods

### Fixed

- A JWKS entry whose RSA `e` or `n` base64-decodes to zero bytes now raises
  `JwksException`. The `is_string()` guard passed such values through, and
  `xmlseclibs` 4.0 answers them with a bare `\Exception` that would escape
  `validateIdToken()` without implementing `OpenIdConnectExceptionInterface`.
  The check sits after the decode because `""`, `" "` and `"\n"` all decode to
  zero bytes. On `xmlseclibs` 3.1.5 the same input threw nothing and silently
  built a key from an empty modulus, which then failed signature verification

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
