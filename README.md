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

Then create a provider and redirect to the authorization url

```
$provider = new OpenIdConfigurationProvider([
            'redirectUrl' => 'https://some.url', // Absolute url to where the user is redirected after a successful login            
            'urlConfiguration' => 'https://.../openid-configuration', // url to OpenId configuration
            'cachePath' => '/some/directory/openId-cache.php', // Path for caching above configuration document
            'clientId'=> 'client_id', // Client id assigned by Azure
            'clientSecret'=> 'client_secret', // Client password assigned by Azure
        ]);

$authUrl = $provider->getAuthorizationUrl();

// direct client to $authUrl
```

Note that the default response type and mode
is set in ```OpenIdConfigurationProvider.php```

```
'response_type' => 'id_token',
'response_mode' => 'query',
```

## Coding standards

The coding standard we use...

## Versioning

We use [SemVer](http://semver.org/) for versioning.

## License 
This project is licensed under the MIT License - see the
[LICENSE.md](LICENSE.md) file for details