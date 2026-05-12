<?php

namespace ItkDev\OpenIdConnect\Exception;

/**
 * Thrown when the `leeway` option is a negative integer. Leeway adjusts
 * clock-skew tolerance during JWT exp/iat validation and must be ≥ 0 —
 * negative leeway would push the validation window into the future. Hence
 * `\InvalidArgumentException`.
 *
 * Distinct from {@see ConfigurationException} (the option is missing
 * entirely).
 */
class NegativeLeewayException extends \InvalidArgumentException implements OpenIdConnectExceptionInterface
{
}
