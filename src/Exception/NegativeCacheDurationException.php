<?php

namespace ItkDev\OpenIdConnect\Exception;

/**
 * Thrown when the `cacheDuration` option is a negative integer. Cache TTL
 * must be ≥ 0 seconds; a negative value is meaningless. Hence
 * `\InvalidArgumentException` (the value is structurally a valid int, but
 * out of the accepted range).
 *
 * Distinct from {@see ConfigurationException} (the option is missing
 * entirely).
 */
class NegativeCacheDurationException extends \InvalidArgumentException implements OpenIdConnectExceptionInterface
{
}
