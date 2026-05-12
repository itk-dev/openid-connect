<?php

namespace ItkDev\OpenIdConnect\Exception;

/**
 * Thrown when the JWKS payload returned from the IdP doesn't conform to
 * RFC 7517 (JSON Web Key Set) — the top-level `keys` array is missing,
 * an entry isn't a JSON object, a required field (`kid`, `kty`, RSA `e`
 * / `n`) is missing or has the wrong type, or the `kty` is one this
 * library doesn't support. Hence `\RuntimeException` (a persistent IdP
 * configuration issue; retry won't help).
 *
 * Distinct from {@see DecodeException} (a JWK's base64 bytes are
 * malformed but the structure is OK), from {@see MetadataException} (the
 * OIDC discovery document — not the JWKS — is malformed), and from
 * {@see JsonException} (the bytes didn't parse as JSON at all).
 */
class JwksException extends \RuntimeException implements OpenIdConnectExceptionInterface
{
}
