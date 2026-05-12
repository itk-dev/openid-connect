<?php

namespace ItkDev\OpenIdConnect\Exception;

/**
 * Thrown when `openIDConnectMetadataUrl` uses the `http://` scheme without
 * the explicit `allowHttp: true` opt-in. OIDC requires TLS; plain HTTP is
 * only acceptable for local IdP mocks during development. A programmer
 * error — both the URL and the opt-in are configuration, fixed in code or
 * env. Hence `\LogicException`.
 *
 * Distinct from {@see BadUrlException} (URL syntax is unparseable).
 */
class IllegalSchemeException extends \LogicException implements OpenIdConnectExceptionInterface
{
}
