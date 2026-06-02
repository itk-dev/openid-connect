<?php

namespace ItkDev\OpenIdConnect\Exception;

/**
 * Thrown by the internal base64url decoder when a JWK's `e` (exponent) or
 * `n` (modulus) string contains bytes that fail strict base64 decoding.
 * The JWK is structurally OK (per RFC 7517) but its contents are
 * unparseable. Hence `\RuntimeException`.
 *
 * Distinct from {@see JwksException} (the JWK structure itself is wrong
 * — missing `kid` / `kty`, non-array key entry, etc.). Both can fire
 * while loading the JWKS, but at different levels: JwksException at the
 * shape level, DecodeException at the bytes level.
 */
class DecodeException extends \RuntimeException implements OpenIdConnectExceptionInterface
{
}
