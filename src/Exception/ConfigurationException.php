<?php

namespace ItkDev\OpenIdConnect\Exception;

/**
 * Thrown when the bundle is misconfigured (missing required constructor option, invalid value, etc).
 *
 * Extends `\InvalidArgumentException` because the failure is invalid input to a public constructor;
 * fixable in calling code, not at runtime.
 */
class ConfigurationException extends \InvalidArgumentException implements OpenIdConnectExceptionInterface
{
}
