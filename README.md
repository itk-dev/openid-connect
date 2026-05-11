# OpenID Connect

[![Github](https://img.shields.io/badge/source-itk--dev/openid--connect-blue?style=flat-square)](https://github.com/itk-dev/openid-connect)
[![Release](https://img.shields.io/packagist/v/itk-dev/openid-connect.svg?style=flat-square&label=release)](https://packagist.org/packages/itk-dev/openid-connect)
[![PHP Version](https://img.shields.io/packagist/php-v/itk-dev/openid-connect.svg?style=flat-square&colorB=%238892BF)](https://www.php.net/downloads)
[![Build Status](https://img.shields.io/github/actions/workflow/status/itk-dev/openid-connect/php.yaml?branch=develop&label=CI&logo=github&style=flat-square)](https://github.com/itk-dev/openid-connect/actions/workflows/php.yaml?query=branch%3Adevelop)
[![Codecov Code Coverage](https://img.shields.io/codecov/c/gh/itk-dev/openid-connect?label=codecov&logo=codecov&style=flat-square)](https://codecov.io/gh/itk-dev/openid-connect)
[![Read License](https://img.shields.io/packagist/l/itk-dev/openid-connect.svg?style=flat-square&colorB=darkcyan)](https://github.com/itk-dev/openid-connect/blob/master/LICENSE.md)
[![Package downloads on Packagist](https://img.shields.io/packagist/dt/itk-dev/openid-connect.svg?style=flat-square&colorB=darkmagenta)](https://packagist.org/packages/itk-dev/openid-connect/stats)

Composer package for configuring OpenID Connect via
[OpenID Connect Discovery document](https://openid.net/specs/openid-connect-discovery-1_0.html).

This library is made and tested for use with [Azure AD B2C](https://docs.microsoft.com/en-us/azure/active-directory-b2c/)
but should be usable for other OpenID Connect providers.

## References

* [OpenID Connect Implicit Client Implementer's Guide 1.0](https://openid.net/specs/openid-connect-implicit-1_0.html)
* [Azure Active Directory B2C documentation](https://docs.microsoft.com/en-us/azure/active-directory-b2c/)
* [Web sign-in with OpenID Connect in Azure Active Directory B2C](https://docs.microsoft.com/en-us/azure/active-directory-b2c/openid-connect#send-authentication-requests)

## Usage

### Framework

If you are looking to use this in a Symfony or Drupal project you should use
either:

* Symfony: [itk-dev/openid-connect-bundle](https://github.com/itk-dev/openid-connect-bundle)
* (Archived) ~~Drupal: [itk-dev/itkdev_openid_connect_drupal](https://github.com/itk-dev/itkdev_openid_connect_drupal)~~

### Direct Installation

To install this library directly run

```shell
composer require itk-dev/openid-connect
```

To use the library you must provide a cache implementation of [PSR-6: Caching Interface](https://www.php-fig.org/psr/psr-6/).
Look to [PHP Cache](http://www.php-cache.com/en/latest/) for documentation and
implementations.

### Direct usage

#### Flow

When a user wishes to authenticate themselves, we create an instance of
`OpenIdConfigurationProvider` and redirect them to the authorization url this
provides.
Here the user can authenticate and if successful be redirected back the
redirect uri provided. During verification of the response from the authorizer
we can extract information about the user from the `id_token`, depending on
which claims are supported.

#### Configuration

To use the package import the namespace, create and configure
a provider

```php
require_once __DIR__.'/vendor/autoload.php';

use ItkDev\OpenIdConnect\Security\OpenIdConfigurationProvider;

$provider = new OpenIdConfigurationProvider([
    'redirectUri' => 'https://some.url', // Absolute url to where the user is redirected after a successful login
    'openIDConnectMetadataUrl' => 'https:/.../openid-configuration', // url to OpenId Discovery document
    'cacheItemPool' => 'Psr6/CacheItemPoolInterface', // Implementation of CacheItemPoolInterface for caching above discovery document
    'clientId' => 'client_id', // Client id assigned by authorizer
    'clientSecret' => 'client_secret', // Client password assigned by authorizer
    // optional values
    'leeway' => 30, // Defaults to 10 (seconds)
    'cacheDuration' => 3600, // Defaults to 86400 (seconds)
    'allowHttp' => true, // Defaults to false. Allow OIDC urls with http scheme. Use only during development!
]);
```

##### HTTP timeout, proxy, and TLS verification

This library extends `league/oauth2-client`, which uses Guzzle for HTTP. To
bound how long a request to the IdP can take (recommended for production),
pass `timeout` (seconds) in the constructor `$options`:

```php
$provider = new OpenIdConfigurationProvider([
    // ... required options ...
    'timeout' => 5,
    'proxy' => 'http://proxy.example.com:8080',
    'verify' => true, // only consulted by Guzzle when proxy is set
]);
```

`league/oauth2-client` whitelists exactly these three keys (`timeout`, `proxy`,
`verify`) and forwards them to the underlying Guzzle client. Other Guzzle
options (e.g. `connect_timeout`) are silently dropped.

> **Why Guzzle and not Symfony HttpClient?**
> `league/oauth2-client` hard-types its HTTP client as
> `GuzzleHttp\ClientInterface`. Symfony HttpClient implements PSR-18 / HTTPlug,
> not Guzzle's interface, and there is no maintained adapter going Symfony →
> Guzzle. To plug in a non-Guzzle client you would need to write such an
> adapter yourself and pass it via `$collaborators['httpClient']` to the
> constructor.

##### Leeway

To account for clock skew times between the signing and verifying servers,
you can set a leeway when configuring the provider. It is recommended that
leeway should not be bigger than a few minutes.

Defaults to 10 seconds

For more information see the following:

* [firebase/php-jwt](https://github.com/firebase/php-jwt#example)
  Last entry in the example mentions the leeway option.

* [JWT documentation](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#nbfDef)

#### Non-authorized requests

Non-authorized requests should be redirected to the authorization url.

To generate the authorization url you must supply "state" and "nonce":

State:
_"A value included in the request that's also returned in the token response.
It can be a string of any content that you want. A randomly generated unique
value is typically used for preventing cross-site request forgery attacks.
The state is also used to encode information about the user's state in the
application before the authentication request occurred, such as the page they
were on."_

Nonce:
_"A value included in the request (generated by the application) that is
included in the resulting ID token as a claim. The application can then verify
this value to mitigate token replay attacks. The value is typically a randomized
unique string that can be used to identify the origin of the request."_

See: [Send authentication requests](https://docs.microsoft.com/en-us/azure/active-directory-b2c/openid-connect#send-authentication-requests)

You must persist these locally so that they can be used to validate the token
when the user is redirected back to your application.

```php
// Get "state" and "nonce"
$state = $provider->generateState();
$nonce = $provider->generateNonce();

// Save to session
$session->set('oauth2state', $state);
$session->set('oauth2nonce', $nonce);

$authUrl = $provider->getAuthorizationUrl(['state' => $state, 'nonce' => $nonce]);

// redirect to $authUrl
```

Note that the default response type and mode
is set in ```OpenIdConfigurationProvider.php```

```php
'response_type' => 'id_token',
'response_mode' => 'query',
```

#### Verify authorized requests

The authorization service will redirect the user back to the `redirectUri`. This
should be an endpoint in your application where you validate the token and the
user.

Load the "state" and "nonce" from local storage and validate against the request
values

```php
// Validate that the request state and session state match
$sessionState = $this->session->get('oauth2state');
$this->session->remove('oauth2state');
if (!$sessionState || $request->query->get('state') !== $sessionState) {
    throw new ValidationException('Invalid state');
}

// Validate the id token. This will validate the token against the keys published by the
// provider (Azure AD B2C). If the token is invalid or the nonce doesn't match an
// exception will thrown.
try {
    $claims = $provider->validateIdToken($request->query->get('id_token'), $session->get('oauth2nonce'));
    // Authentication successful
} catch (ItkOpenIdConnectException $exception) {
    // Handle failed authentication
} finally {
    $this->session->remove('oauth2nonce');
}
```

## Development Setup

A `docker-compose.yml` file with a PHP 8.3+ image is included in this project.
A [Taskfile](https://taskfile.dev/) is used to run common development tasks.

To set up the project:

```shell
task setup
```

This starts the Docker containers and installs Composer dependencies.

### Running All CI Checks

To run all checks locally (coding standards, static analysis, tests):

```shell
task pr:actions
```

### Unit Testing

```shell
task test
```

### Test Matrix

Run the test suite across all supported PHP versions (8.3, 8.4, 8.5) with both
lowest and stable dependencies, mirroring the CI matrix:

```shell
task test:matrix
```

This runs PHPUnit with coverage for each combination and prints a summary of
pass/fail results.

The test suite uses [Mockery](https://github.com/mockery/mockery) to mock
[public static methods](http://docs.mockery.io/en/latest/reference/public_static_properties.html?highlight=static)
in 3rd party libraries like the `JWT::decode` method from `firebase/jwt`.

### PHPStan Static Analysis

```shell
task analyze
```

### Coding Standards

Check all coding standards:

```shell
task lint
```

Fix PHP coding standards (php-cs-fixer):

```shell
task lint:php:fix
```

Fix Markdown files:

```shell
task lint:markdown:fix
```

Fix YAML files:

```shell
task lint:yaml:fix
```

### Available Tasks

Run `task --list` to see all available tasks.

## CI

GitHub Actions are used to run the test suite and code style checks on all PRs.

## Versioning

We use [SemVer](http://semver.org/) for versioning.
For the versions available, see the
[tags on this repository](https://github.com/itk-dev/openid-connect/tags).

## License

This project is licensed under the MIT License - see the
[LICENSE.md](LICENSE.md) file for details
