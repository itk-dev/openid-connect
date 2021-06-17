# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

## [Unreleased]

### Added

- Release links in CHANGELOG

### Fixed

- Fixed validation example in README
- Fixed coding standards commands in package.json

## [2.1.0] - 2021-06-14

### Added

- Leeway option when validating id token

## [2.0.0] - 2021-06-04

### Added

- Test suite
- Psalm setup for static analysis
- Code formatting

### Fixed

- Fixed security issue, where token was not validated against the signing keys

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

[unreleased]: https://github.com/itk-dev/openid-connect/compare/2.1.0...HEAD
[2.1.0]: https://github.com/itk-dev/openid-connect/compare/2.0.0...2.1.0
[2.0.0]: https://github.com/itk-dev/openid-connect/compare/1.0.0...2.0.0
[1.0.0]: https://github.com/itk-dev/openid-connect/releases/tag/1.0.0
