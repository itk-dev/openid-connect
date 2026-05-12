<?php

namespace ItkDev\OpenIdConnect\Exception;

use Psr\Http\Client\ClientExceptionInterface;

class HttpException extends \RuntimeException implements OpenIdConnectExceptionInterface, ClientExceptionInterface
{
}
