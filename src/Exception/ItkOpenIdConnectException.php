<?php

namespace ItkDev\OpenIdConnect\Exception;

/**
 * @deprecated since 5.0, will be removed in 6.0. Catch
 *   {@see OpenIdConnectExceptionInterface} instead. Concrete exception classes
 *   no longer extend this abstract; existing `catch (ItkOpenIdConnectException $e)`
 *   blocks will not match any exception thrown by 5.0+ code.
 */
abstract class ItkOpenIdConnectException extends \Exception implements OpenIdConnectExceptionInterface
{
}
