<?php

namespace ItkDev\OpenIdConnect\Exception;

/**
 * Thrown from `getAuthorizationUrl()` when the caller omitted the required
 * `state` or `nonce` parameter. Both are CSRF / replay-attack mitigations
 * mandated by the OIDC spec — calling code is expected to generate and
 * pass them on every authorization request. A programmer error in the
 * calling code, hence `\LogicException`.
 */
class MissingParameterException extends \LogicException implements OpenIdConnectExceptionInterface
{
}
