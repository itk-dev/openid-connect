# OpenID Connect

Composer package for configuring OpenID Connect via
[OpenID Connect Discovery document](https://openid.net/specs/openid-connect-discovery-1_0.html).

## Usage

For Symfony or Drupal projects you should use either:

* Symfony: [itk-dev/openid-connect-bundle](https://github.com/itk-dev/openid-connect-bundle)
* Drupal: [itk-dev/itkdev_openid_connect_drupal](https://github.com/itk-dev/itkdev_openid_connect_drupal)

### Direct Installation

To install this library directly run

```shell
composer require itk-dev/openid-connect
```

### Flow

When a user wishes to authenticate themselves, we create an instance of
`OpenIdConfigurationProvider` and direct them to the authorization url this provides.
Here the user can authenticate and if successful be redirected back the uri provided.
During verification of the response from the authorizer we can extract
information about the user from the `id_token`, depending on which claims are supported.

### Configuration

To use the package import the namespace, create and configure
a provider and then direct them to the authorization url.

```php
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

```php
'response_type' => 'id_token',
'response_mode' => 'query',
```

## Development Setup

A `docker-compose.yml` file with a PHP 7.4 image is included in this project.
To install the dependencies you can run

```shell
docker compose up -d
docker compose exec phpfpm composer install
```

### Unit Testing

A standard PhpUnit setup is included in this library. To run the unit tests:

    ```shell
    docker compose exec phpfpm composer install
    docker compose exec phpfpm ./vendor/bin/phpunit
    ``` 

### Check Coding Standard

The following command let you test that the code follows
the coding standard we decided to adhere to in this project.

* PHP files (PHP-CS-Fixer)

    ```shell
    docker compose exec phpfpm composer check-coding-standards
    ```

* Markdown files (markdownlint standard rules)
  
    ```shell
    docker run -v ${PWD}:/app itkdev/yarn:latest install
    docker run -v ${PWD}:/app itkdev/yarn:latest check-coding-standards
    ```
  
### Apply Coding Standards

To attempt to automatically fix coding style

* PHP files (PHP-CS-Fixer)

    ```sh
    docker compose exec phpfpm composer apply-coding-standards
    ```

* Markdown files (markdownlint standard rules)

    ```shell
    docker run -v ${PWD}:/app itkdev/yarn:latest install
    docker run -v ${PWD}:/app itkdev/yarn:latest check-coding-standards
    ```
  
## CI

Github Actions are used to run the test suite and code style checks on all PR's. 

If you wish to test against the jobs locally you can install `act` (https://github.com/nektos/act). 
Then do:  
  ```shell
  act -P ubuntu-latest=shivammathur/node:latest pull_request
  ```

## Versioning

We use [SemVer](http://semver.org/) for versioning.
For the versions available, see the
[tags on this repository](https://github.com/itk-dev/openid-connect/tags).

## License

This project is licensed under the MIT License - see the
[LICENSE.md](LICENSE.md) file for details
