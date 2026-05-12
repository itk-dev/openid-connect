<?php

namespace ItkDev\OpenIdConnect\Exception;

/**
 * Thrown from `validateIdToken()` when the ID token cannot be
 * cryptographically validated — bad signature, expired, malformed JWT
 * structure, or any failure inside `firebase/php-jwt`'s
 * `JWT::decode()` (wraps `\UnexpectedValueException` and chains the
 * cause via `$previous`). Hence `\RuntimeException` (often resolves by
 * re-authenticating, since a fresh login produces a fresh token).
 *
 * Distinct from {@see ClaimsException} (the token decoded successfully
 * but its claim *values* — audience, issuer, nonce — are wrong) and
 * from {@see CodeException} (the failure was getting the token in the
 * first place, before decode).
 */
class ValidationException extends \RuntimeException implements OpenIdConnectExceptionInterface
{
}
