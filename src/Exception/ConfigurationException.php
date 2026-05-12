<?php

namespace ItkDev\OpenIdConnect\Exception;

/**
 * Thrown from the `OpenIdConfigurationProvider` constructor when a required
 * option (`cacheItemPool`, `openIDConnectMetadataUrl`) is missing from the
 * `$options` array. Invalid input to a public constructor — fixable in
 * calling code only. Hence `\InvalidArgumentException`.
 *
 * Distinct from {@see NegativeCacheDurationException} and
 * {@see NegativeLeewayException}, which fire when a numeric option is
 * present but out of range.
 */
class ConfigurationException extends \InvalidArgumentException implements OpenIdConnectExceptionInterface
{
}
