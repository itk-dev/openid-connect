<?php

namespace ItkDev\OpenIdConnect\Exception;

use Psr\Http\Client\ClientExceptionInterface;

/**
 * Wraps HTTP transport failures while fetching the OIDC discovery document
 * or the JWKS — non-200 responses, network errors, or Guzzle-thrown
 * `Psr\Http\Client\ClientExceptionInterface` from the underlying HTTP
 * client (chained via `$previous`). Hence `\RuntimeException` (transient —
 * the IdP being briefly unreachable typically resolves on retry).
 *
 * Also implements PSR-18's {@see ClientExceptionInterface} as part of the
 * public contract: PSR-18-aware consumers can catch HTTP failures from
 * this library via the standard PSR marker.
 *
 * Distinct from {@see CodeException} (failure during the OAuth code
 * exchange POST to the token endpoint).
 */
class HttpException extends \RuntimeException implements OpenIdConnectExceptionInterface, ClientExceptionInterface
{
}
