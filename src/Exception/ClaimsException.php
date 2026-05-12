<?php

namespace ItkDev\OpenIdConnect\Exception;

/**
 * Thrown from `validateIdToken()` when the decoded ID token's claims
 * don't match expectations — wrong `aud` (audience does not contain
 * our client id), wrong `iss` (issuer doesn't match the discovery
 * document), or wrong `nonce` (didn't match the value we sent on the
 * authorization request). Hence `\RuntimeException` (typically requires
 * either re-authenticating, or auditing why the IdP issued a token
 * meant for someone else — security-relevant if persistent).
 *
 * Distinct from {@see ValidationException} (token cryptographically
 * invalid — bad signature, expired) and from {@see CodeException}
 * (failure obtaining the token in the first place, before decoding).
 */
class ClaimsException extends \RuntimeException implements OpenIdConnectExceptionInterface
{
}
