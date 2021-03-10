# Work in progress

# OpenID Connect

Composer package for configuring OpenID Connect via
[OpenID Connect Discovery document](https://openid.net/specs/openid-connect-discovery-1_0.html).

## Installation

To install run

```shell
composer require itk-dev/openid-connect
```

## Usage

To use the package import the namespace, create
a provider and direct to the authorization url.

```sh
<?php

require_once __DIR__.'/vendor/autoload.php';

use ItkDev\OpenIdConnect\Security\OpenIdConfigurationProvider;

$provider = new OpenIdConfigurationProvider([
    'redirectUri' => 'https://some.url', // Absolute url to where the user is redirected after a successful login            
    'urlConfiguration' => 'https:/.../openid-configuration', // url to OpenId Discovery document
    'cachePath' => '/some/directory/openId-cache.php', // Path for caching above discovery document
    'clientId'=> 'client_id', // Client id assigned by authorizer
    'clientSecret'=> 'client_secret', // Client password assigned by authorizer
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

If you wish to see the package used in a Symfony project:

* How to [bind $openIdProviderOptions](https://github.com/itk-dev/naevnssekretariatet/blob/develop/config/services.yaml)
* How to [set the environment variables](https://github.com/itk-dev/naevnssekretariatet/blob/develop/.env)
* How to [create provider and redirect user](https://github.com/itk-dev/naevnssekretariatet/blob/develop/src/Controller/DefaultController.php)
* How to [handle and verify response](https://github.com/itk-dev/naevnssekretariatet/blob/develop/src/Security/OpenIdLoginAuthenticator.php).

## Flow

When a user wishes to authenticate themselves, we create an instance of
`OpenIdConfigurationProvider` and direct them to the authorization url this provides.
Here the user can authenticate 
and if successful be redirected back the uri provided.

## Coding standard tests

The following command let you test that the code follows
the coding standard we decided to adhere to in this project.

* PHP files (PHP-CS-Fixer)

    ```sh
    ./vendor/bin/php-cs-fixer fix src --dry-run
    ```

* Markdown files (markdownlint standard rules)
  
    ```sh
    ./node_modules/.bin/markdownlint --fix *.md
    ```

## Versioning

We use [SemVer](http://semver.org/) for versioning.
See LINK HERE for versions available.

## License

This project is licensed under the MIT License - see the
[LICENSE.md](LICENSE.md) file for details
