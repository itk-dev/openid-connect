<?php

namespace ItkDev\OpenIdConnect\Exception;

/**
 * Marker interface for every exception thrown from a public method of this library.
 *
 * Consumers can catch every OIDC failure with a single `catch (OpenIdConnectExceptionInterface $e)`
 * block, or scope to a more specific concrete subtype when they need to discriminate. Concrete
 * exception classes extend the SPL type that best describes the failure category
 * (`\RuntimeException`, `\LogicException`, `\InvalidArgumentException`) and implement this marker.
 */
interface OpenIdConnectExceptionInterface extends \Throwable
{
}
