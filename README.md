# OpenID Connect

Composer package for OpenID Connect via Azure B2C

## Installation

To install run

```shell
composer require itk-dev/openid-connect
```

## Usage

To use the package create a provider and redirect to the authorization url

```shell
$provider = new OpenIdConfigurationProvider([
            'redirectUri' => $this->generateUrl('default', [], UrlGeneratorInterface::ABSOLUTE_URL),
        ] + $openIdProviderOptions);

$authUrl = $provider->getAuthorizationUrl();

return new RedirectResponse($authUrl);
```

where `$openIdProviderOptions` advantageously could
be injected and bound in the ```services.yaml``` file:

```shell
bind:
  $openIdProviderOptions:
    urlConfiguration: '%env(OPEN_ID_PROVIDER_URL)%'
    cachePath: '%env(resolve:OPEN_ID_PROVIDER_CACHE_PATH)%'
    clientId: '%env(OPEN_ID_PROVIDER_CLIENT_ID)%'
    clientSecret: '%env(OPEN_ID_PROVIDER_CLIENT_SECRET)%'
```
and the environment variables must be set in the ```.env``` or ```.env.local.``` file.


Note that the default response type and mode
is set in ```OpenIdConfigurationProvider.php```

```shell
'response_type' => 'id_token',
'response_mode' => 'query',
```

The Request should then be handled in some sort of GuardAuthenticator

## Tests

To run tests...

## Coding standards

The coding standard we use...

## License 
This project is licensed under the MIT License - see the
[LICENSE.md](LICENSE.md) file for details