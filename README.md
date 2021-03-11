# Work in progress

# OpenID Connect

Composer package for configuring OpenID Connect via
[OpenID Connect Discovery document](https://openid.net/specs/openid-connect-discovery-1_0.html).

## Installation

To install run

```shell
composer require itk-dev/openid-connect
```

If you wish to run the coding standard tests for Markdown files

```sh
yarn install
```

## Flow

When a user wishes to authenticate themselves, we create an instance of
`OpenIdConfigurationProvider` and direct them to the authorization url this provides.
Here the user can authenticate and if successful be redirected back the uri provided.
During verification of the response from the authorizer we can extract
information about the user from the `id_token`, depending on which claims are supported.

## Usage

To use the package import the namespace, create and configure
a provider and then direct them to the authorization url.

```sh
<?php

require_once __DIR__.'/vendor/autoload.php';

use ItkDev\OpenIdConnect\Security\OpenIdConfigurationProvider;

$provider = new OpenIdConfigurationProvider([
    'redirectUri' => 'https://some.url', // Absolute url to where the user is redirected after a successful login            
    'urlConfiguration' => 'https:/.../openid-configuration', // url to OpenId Discovery document
    'cachePath' => '/some/directory/openId-cache.php', // Path for caching above discovery document
    'clientId' => 'client_id', // Client id assigned by authorizer
    'clientSecret' => 'client_secret', // Client password assigned by authorizer
 ]);

$authUrl = $provider->getAuthorizationUrl();

// direct to $authUrl
```

Note that the default response type and mode
is set in ```OpenIdConfigurationProvider.php```

```sh
'response_type' => 'id_token',
'response_mode' => 'query',
```

### Symfony usage example

In Symfony, we create a login route that when accessed starts
the authentication flow. Upon creating an instance of
`OpenIdConfigurationProvider` we configure it with a return URI,
a cache path and some authorizer details.

```sh
use ItkDev\OpenIdConnect\Security\OpenIdConfigurationProvider;

/**
  * @Route("/login", name="login")
  */
public function login(SessionInterface $session, array $openIdProviderOptions = []): Response
{
    $provider = new OpenIdConfigurationProvider([
        'redirectUri' => $this->generateUrl('some_route_here', [], UrlGeneratorInterface::ABSOLUTE_URL),
    ] + $openIdProviderOptions);

    $authUrl = $provider->getAuthorizationUrl();
    
    // Set oauth2state and check it upon receiving respose to avoid CSRF
    $session->set('oauth2state', $provider->getState());

    return new RedirectResponse($authUrl);
}
```

The response from the authorizer should then be processed by a
[Guard Authenticator](https://symfony.com/doc/current/security/guard_authentication.html).

If you wish to see the package used in a Symfony project
check out [naevnssekretariatet](https://github.com/itk-dev/naevnssekretariatet):

* How to [bind $openIdProviderOptions](https://github.com/itk-dev/naevnssekretariatet/blob/develop/config/services.yaml)
* How to [set the environment variables](https://github.com/itk-dev/naevnssekretariatet/blob/develop/.env)
* How to [create provider and redirect user](https://github.com/itk-dev/naevnssekretariatet/blob/develop/src/Controller/DefaultController.php)
* How to [process and verify response](https://github.com/itk-dev/naevnssekretariatet/blob/develop/src/Security/OpenIdLoginAuthenticator.php)

## Coding standard tests

The following command let you test that the code follows
the coding standard we decided to adhere to in this project.

* PHP files (PHP-CS-Fixer)

    ```sh
    ./vendor/bin/php-cs-fixer fix src --dry-run
    ```

* Markdown files (markdownlint standard rules)
  
    ```sh
    yarn coding-standards-check
    ```

## Versioning

We use [SemVer](http://semver.org/) for versioning.
For the versions available, see the
[tags on this repository](https://github.com/itk-dev/openid-connect/tags).

## License

This project is licensed under the MIT License - see the
[LICENSE.md](LICENSE.md) file for details
