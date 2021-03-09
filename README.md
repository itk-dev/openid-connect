# Work in progress

# OpenID Connect

Composer package for OpenID Connect via Azure B2C

## Installation

To install run

```shell
composer require itk-dev/openid-connect
```

## Usage

To use the package import the namespace

```
use ItkDev\OpenIdConnect\Security\OpenIdConfigurationProvider;
```

Then create a provider and direct to the authorization url

```
$provider = new OpenIdConfigurationProvider([
    'redirectUri' => 'https://some.url', // Absolute url to where the user is redirected after a successful login            
    'urlConfiguration' => 'https:/.../openid-configuration', // url to OpenId configuration
    'cachePath' => '/some/directory/openId-cache.php', // Path for caching above configuration document
    'clientId'=> 'client_id', // Client id assigned by Azure
    'clientSecret'=> 'client_secret', // Client password assigned by Azure
 ]);

$authUrl = $provider->getAuthorizationUrl();

// direct to $authUrl
```

Note that the default response type and mode
is set in ```OpenIdConfigurationProvider.php```

```
'response_type' => 'id_token',
'response_mode' => 'query',
```


## Flow

When a user wishes to authenticate themselves, we create an instance of
`OpenIdConfigurationProvider` and direct them to the authorization url.
Here the user can authenticate using their Azure B2C login, and if successful be redirected
back the uri provided when creating the provider instance.

## Coding standard test

The following command let you test that the code follows the coding standard we decided to adhere to in this project.
* PHP files (PHP-CS-Fixer)

    ```
    ./vendor/bin/php-cs-fixer fix src --dry-run
    ```

## Versioning

We use [SemVer](http://semver.org/) for versioning. 
See LINK HERE for versions available.

## License 
This project is licensed under the MIT License - see the
[LICENSE.md](LICENSE.md) file for details