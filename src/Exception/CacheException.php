<?php

namespace ItkDev\OpenIdConnect\Exception;

/**
 * Wraps PSR-6 cache layer failures. Specifically thrown when the injected
 * `Psr\Cache\CacheItemPoolInterface` raises `Psr\Cache\InvalidArgumentException`
 * from `getItem` / `save` / `deleteItem` — typically because the cache key
 * contains a character the backend rejects, or the backend itself is
 * unhealthy. The original exception is chained via `$previous`. Hence
 * `\RuntimeException` (transient — a different cache backend or a sanitized
 * key may resolve it).
 *
 * Strictly cache-layer failures only. Discovery-document validation problems
 * are {@see MetadataException}; JWKS validation problems are
 * {@see JwksException}; JSON parse failures are {@see JsonException}.
 */
class CacheException extends \RuntimeException implements OpenIdConnectExceptionInterface
{
}
