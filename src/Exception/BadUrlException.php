<?php

namespace ItkDev\OpenIdConnect\Exception;

/**
 * Thrown when `openIDConnectMetadataUrl` fails URL syntax validation
 * (`parse_url` rejects it because no scheme can be parsed). A programmer
 * error — the value is hard-coded or comes from misread configuration, so
 * fixing it requires editing code or env config, not retrying at runtime.
 * Hence `\LogicException`.
 *
 * Distinct from {@see IllegalSchemeException} (URL parses successfully but
 * uses an `http://` scheme without `allowHttp: true`).
 */
class BadUrlException extends \LogicException implements OpenIdConnectExceptionInterface
{
}
