<?php

namespace ItkDev\OpenIdConnect\Exception;

/**
 * Thrown by `getIdToken()` when the OAuth authorization-code exchange
 * fails: the token endpoint returned a transport error
 * (`Psr\Http\Client\ClientExceptionInterface`), an OAuth error response
 * (`League\OAuth2\Client\Provider\Exception\IdentityProviderException`),
 * non-JSON body (`\JsonException`), or a JSON body missing a string
 * `id_token`. The originating exception is chained via `$previous`.
 * Hence `\RuntimeException` (often transient — typical causes are an
 * expired or already-used authorization code, or a brief IdP outage).
 *
 * Distinct from {@see HttpException} (general HTTP transport failures
 * for the discovery / JWKS endpoints, not the token-exchange POST). And
 * distinct from {@see ValidationException} / {@see ClaimsException},
 * which fire later in the flow on a successfully-received but invalid
 * token.
 */
class CodeException extends \RuntimeException implements OpenIdConnectExceptionInterface
{
}
