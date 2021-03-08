# Work in progress

# OpenID Connect

Composer package for OpenID Connect via Azure B2C

## Installation

To install run

```shell
composer require itk-dev/openid-connect
```

## Usage

To use the package create a provider and redirect to the authorization url

```
$provider = new OpenIdConfigurationProvider([
            'redirectUri' => $this->generateUrl('default', [], UrlGeneratorInterface::ABSOLUTE_URL),
        ] + $openIdProviderOptions);

$authUrl = $provider->getAuthorizationUrl();

return new RedirectResponse($authUrl);
```

where `$openIdProviderOptions` advantageously could
be injected and bound in the ```services.yaml``` file:

```yaml
services:
  _defaults:
    bind:
      $openIdProviderOptions:
        urlConfiguration: '%env(OPEN_ID_PROVIDER_URL)%'
        cachePath: '%env(resolve:OPEN_ID_PROVIDER_CACHE_PATH)%'
        clientId: '%env(OPEN_ID_PROVIDER_CLIENT_ID)%'
        clientSecret: '%env(OPEN_ID_PROVIDER_CLIENT_SECRET)%'
```
while the environment variables must be set in the ```.env``` or ```.env.local.``` file -
see example beneath

```
OPEN_ID_PROVIDER_URL='https://.../.well-known/openid-configuration...'
OPEN_ID_PROVIDER_CLIENT_ID={app.client.id}
OPEN_ID_PROVIDER_CLIENT_SECRET={app.client.secret}
OPEN_ID_PROVIDER_CACHE_PATH='%kernel.cache_dir%/.well_known_cache.php'
```

Note that the default response type and mode
is set in ```OpenIdConfigurationProvider.php```

```
'response_type' => 'id_token',
'response_mode' => 'query',
```

The request should then be handled in some sort of GuardAuthenticator

## Tests

To run tests...

## Coding standards

The coding standard we use...

## License 
This project is licensed under the MIT License - see the
[LICENSE.md](LICENSE.md) file for details