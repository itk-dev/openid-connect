# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

## [Unreleased]

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

[unreleased]: https://github.com/itk-dev/openid-connect/compare/3.2.0...HEAD
[3.1.0]: https://github.com/itk-dev/openid-connect/compare/3.1.0...3.2.0
[3.0.0]: https://github.com/itk-dev/openid-connect/compare/3.0.0...3.1.0
[2.2.0]: https://github.com/itk-dev/openid-connect/compare/2.2.0...2.3.0
[2.1.0]: https://github.com/itk-dev/openid-connect/compare/2.1.0...2.2.0
[2.1.0]: https://github.com/itk-dev/openid-connect/compare/2.0.0...2.1.0
[2.0.0]: https://github.com/itk-dev/openid-connect/compare/1.0.0...2.0.0
[1.0.0]: https://github.com/itk-dev/openid-connect/releases/tag/1.0.0
