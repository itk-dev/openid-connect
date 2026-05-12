# Upgrading from 4.x to 5.0

5.0 reworks the exception hierarchy and tightens several IdP-payload
validations. The runtime behaviour is unchanged for spec-compliant IdPs
— this document covers the consumer-visible API changes you'll need to
adjust catch blocks for.

## Catch the marker interface, not the abstract

Concrete exception classes no longer extend
`\ItkDev\OpenIdConnect\Exception\ItkOpenIdConnectException`. Existing
catches against the abstract will not match anything thrown by 5.0+
code:

```diff
- } catch (\ItkDev\OpenIdConnect\Exception\ItkOpenIdConnectException $e) {
+ } catch (\ItkDev\OpenIdConnect\Exception\OpenIdConnectExceptionInterface $e) {
```

The abstract class is kept through the 5.x line as a `@deprecated`
alias that still implements the marker; removal is scheduled for 6.0.

A consumer that needs to discriminate by failure category can scope to
the concrete's SPL parent instead — catching `\RuntimeException`
matches every transient/data failure (network, cache, token
validation, claims mismatch); catching `\LogicException` matches the
programmer-error variants (`BadUrlException`,
`IllegalSchemeException`, `MissingParameterException`); catching
`\InvalidArgumentException` matches the invalid-constructor-input
variants (`ConfigurationException`, `NegativeCacheDurationException`,
`NegativeLeewayException`).

## Catch on `\InvalidArgumentException` still works for constructor errors

`OpenIdConfigurationProvider::__construct` previously threw raw
`\InvalidArgumentException` for missing required options. It now
throws the typed `ConfigurationException`, which still **extends**
`\InvalidArgumentException`. Existing catches at the SPL level
continue to match without any change:

```php
try {
    new OpenIdConfigurationProvider([]);
} catch (\InvalidArgumentException $e) { // still catches in 5.0
    // ...
}
```

## New typed throws where 4.x silently coerced

Three sites that previously cast malformed IdP-returned values to
strings now throw a typed exception:

- **Malformed JWKS payload (`keys` array missing, JWK entry without
  string `kid` / `kty` / `e` / `n`)** → `JwksException`. 4.x silently
  built a degraded `Key` from whatever the (string) cast produced, or
  tripped a downstream type error in `XMLSecurityKey::convertRSA`.
- **OIDC discovery doc with missing / non-string required key** →
  `MetadataException` (was bubbled as `CacheException`, semantically
  misleading — the failure is the IdP-returned payload not
  conforming to the OIDC Discovery spec, not the cache layer
  misbehaving).
- **Token endpoint response missing string `id_token`** →
  `CodeException` (was a return of `mixed` that produced confusing
  errors at the call site).

If you've been catching `CacheException` specifically for the
missing-config-key case, you'll need to widen to the marker interface
or to `MetadataException`:

```diff
  try {
      $provider->getBaseAuthorizationUrl();
- } catch (\ItkDev\OpenIdConnect\Exception\CacheException $e) {
+ } catch (\ItkDev\OpenIdConnect\Exception\MetadataException $e) {
      // Discovery document is malformed
  }
```

`CacheException` still fires for PSR-6 cache-layer failures (its
strictly-cache-only meaning in 5.0).

## `getIdToken`'s `@throws` no longer advertises `ClientExceptionInterface`

The previous `@throws ClientExceptionInterface` declaration on
`getIdToken` documented a dead-code path — the body's catch-all
wrapped the transport exception into `CodeException` before it could
surface. The declaration was removed in 4.1.2 already; the 5.0 boundary
catch is now narrowed to
`IdentityProviderException|ClientExceptionInterface|\JsonException`
explicitly, but the public type returned to the caller remains
`CodeException` (with the cause chained via `$previous`).

If you were catching `ClientExceptionInterface` after a `getIdToken`
call to handle transport failures specifically, switch to catching
`CodeException` and inspect `$e->getPrevious()` for the original
PSR-18 exception:

```diff
  try {
      $idToken = $provider->getIdToken($code);
- } catch (\Psr\Http\Client\ClientExceptionInterface $e) {
-     // transport failure
+ } catch (\ItkDev\OpenIdConnect\Exception\CodeException $e) {
+     $transport = $e->getPrevious();
+     if ($transport instanceof \Psr\Http\Client\ClientExceptionInterface) {
+         // transport failure
+     }
  }
```

(`HttpException` — fired by the *discovery* / JWKS fetches, not the
token-exchange POST — still implements `ClientExceptionInterface` as
part of its public contract.)

## Catch-on-SPL semantic change

The re-parenting onto SPL types means catches on `\RuntimeException`,
`\LogicException`, or `\InvalidArgumentException` now match OIDC
failures where they previously did not. Concretely: a generic retry
decorator wrapping `validateIdToken` with `catch (\RuntimeException
$e)` will now retry on `CacheException`, `HttpException`,
`ValidationException`, `ClaimsException`, etc.

This is the intended semantic — `\RuntimeException` represents
"transient or data-shape failure," which is exactly what those
concrete types now signal. If your wrapping logic relies on the old
behaviour, narrow the catch to a more specific bundle / library
exception.

## Per-class summary

| Concrete | Parent | When it fires |
| --- | --- | --- |
| `BadUrlException` | `\LogicException` | `openIDConnectMetadataUrl` syntax invalid |
| `IllegalSchemeException` | `\LogicException` | http scheme without `allowHttp: true` |
| `MissingParameterException` | `\LogicException` | `getAuthorizationUrl()` missing required `state` / `nonce` |
| `ConfigurationException` | `\InvalidArgumentException` | Constructor missing `cacheItemPool` / `openIDConnectMetadataUrl` |
| `NegativeCacheDurationException` | `\InvalidArgumentException` | `cacheDuration` < 0 |
| `NegativeLeewayException` | `\InvalidArgumentException` | `leeway` < 0 |
| `CacheException` | `\RuntimeException` | PSR-6 cache layer failed |
| `HttpException` (+ `ClientExceptionInterface`) | `\RuntimeException` | HTTP transport failure for discovery / JWKS |
| `JsonException` | `\RuntimeException` | `json_decode` failed on an IdP response body |
| `DecodeException` | `\RuntimeException` | JWK base64 decode failed |
| `JwksException` | `\RuntimeException` | JWKS payload doesn't conform to RFC 7517 |
| `CodeException` | `\RuntimeException` | Token endpoint exchange failed |
| `ValidationException` | `\RuntimeException` | JWT signature / decode failed |
| `ClaimsException` | `\RuntimeException` | JWT claim values wrong (aud / iss / nonce) |
| `MetadataException` | `\RuntimeException` | OIDC discovery document doesn't conform to the spec |
