<?php

namespace ItkDev\OpenIdConnect\Exception;

/**
 * Thrown when the IdP-returned OIDC discovery metadata does not conform to the
 * OIDC Discovery spec — for example, a required key is missing or has the
 * wrong type. Distinct from `JsonException` (the document didn't even parse)
 * and `CacheException` (the cache layer failed): the JSON parsed fine, the
 * cache is fine, but the document's contents are structurally invalid.
 *
 * Consumers typically can't recover by retrying — the IdP needs to fix the
 * payload — so a `catch (MetadataException $e)` block normally logs + alerts.
 */
class MetadataException extends \RuntimeException implements OpenIdConnectExceptionInterface
{
}
