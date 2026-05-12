<?php

namespace ItkDev\OpenIdConnect\Exception;

/**
 * Thrown when `json_decode` fails on an IdP response body — the bytes
 * didn't parse as JSON at all (raw `\JsonException` from PHP's JSON
 * extension, chained via `$previous`). Hence `\RuntimeException`.
 *
 * Distinct from {@see MetadataException} (JSON parses fine but doesn't
 * conform to the OIDC Discovery spec). The remediation differs: a parse
 * failure may be transient (corrupted bytes, retry might help), while a
 * malformed discovery document is a persistent IdP-configuration issue.
 */
class JsonException extends \RuntimeException implements OpenIdConnectExceptionInterface
{
}
