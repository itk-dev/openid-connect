<?php

declare(strict_types=1);

namespace ItkDev\OpenIdConnect\Security;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use ItkDev\OpenIdConnect\Exception\BadUrlException;
use ItkDev\OpenIdConnect\Exception\CacheException;
use ItkDev\OpenIdConnect\Exception\ClaimsException;
use ItkDev\OpenIdConnect\Exception\CodeException;
use ItkDev\OpenIdConnect\Exception\ConfigurationException;
use ItkDev\OpenIdConnect\Exception\DecodeException;
use ItkDev\OpenIdConnect\Exception\HttpException;
use ItkDev\OpenIdConnect\Exception\IllegalSchemeException;
use ItkDev\OpenIdConnect\Exception\JsonException;
use ItkDev\OpenIdConnect\Exception\JwksException;
use ItkDev\OpenIdConnect\Exception\MetadataException;
use ItkDev\OpenIdConnect\Exception\MissingParameterException;
use ItkDev\OpenIdConnect\Exception\NegativeCacheDurationException;
use ItkDev\OpenIdConnect\Exception\NegativeLeewayException;
use ItkDev\OpenIdConnect\Exception\OpenIdConnectExceptionInterface;
use ItkDev\OpenIdConnect\Exception\ValidationException;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericResourceOwner;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\RequestFactory;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Cache\InvalidArgumentException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Class OpenIdConfigurationProvider.
 *
 * @see https://github.com/cirrusidentity/simplesamlphp-module-authoauth2/blob/master/src/Providers/OpenIDConnectProvider.php
 */
class OpenIdConfigurationProvider extends AbstractProvider
{
    private const string CACHE_KEY_PREFIX = 'itk-openid-connect-configuration-';

    // The only signature algorithm this provider accepts. Passed to
    // JWK::parseKey() as the default for JWKS entries that omit "alg", which is
    // the common case (Azure AD B2C, Keycloak).
    private const string SIGNING_ALGORITHM = 'RS256';

    // Upper bound on the discovery document and the JWKS. Both are small — a
    // few kilobytes in practice — so a mebibyte is generous while still keeping
    // a hostile or misconfigured endpoint from handing us an unbounded body to
    // decode and cache.
    private const int MAX_JSON_RESOURCE_BYTES = 1048576;

    // @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
    private const string POST_LOGOUT_REDIRECT_URI = 'post_logout_redirect_uri';
    private const string ID_TOKEN_HINT = 'id_token_hint';

    private const string STATE = 'state';

    private string $responseError = 'error';

    protected string $openIDConnectMetadataUrl;

    private ?CacheItemPoolInterface $cacheItemPool = null;

    private int $cacheDuration = 86400;

    private int $leeway = 10;

    private string $responseResourceOwnerId = 'id';

    private bool $allowHttp = false;

    /**
     * OpenIdConfigurationProvider constructor.
     *
     * The two well-typed keys (`cacheItemPool`, `openIDConnectMetadataUrl`)
     * are marked optional in the array shape because the runtime check
     * throws `ConfigurationException` if they are missing — but their type
     * is narrowed when present so the downstream setters keep their typed
     * arguments. Extra keys (league/oauth2-client's `clientId`,
     * `clientSecret`, `redirectUri`, … and Guzzle's `timeout` / `proxy` /
     * `verify`) are accepted via `...`.
     *
     * @param array{
     *     cacheItemPool?: CacheItemPoolInterface,
     *     openIDConnectMetadataUrl?: string,
     *     cacheDuration?: int,
     *     leeway?: int,
     *     allowHttp?: bool,
     *     ...
     * } $options
     * @param array{
     *     jwt?: \League\OAuth2\Client\Tool\RequestFactory,
     *     httpClient?: \GuzzleHttp\ClientInterface,
     *     ...
     * } $collaborators
     *
     * @throws OpenIdConnectExceptionInterface
     */
    public function __construct(array $options = [], array $collaborators = [])
    {
        parent::__construct($options, $collaborators);

        if (!array_key_exists('cacheItemPool', $options)) {
            throw new ConfigurationException('Required options not defined: cacheItemPool');
        }
        $this->setCacheItemPool($options['cacheItemPool']);

        if (array_key_exists('cacheDuration', $options)) {
            $this->setCacheDuration($options['cacheDuration']);
        }

        if (array_key_exists('leeway', $options)) {
            $this->setLeeway($options['leeway']);
        }

        if (!array_key_exists('openIDConnectMetadataUrl', $options)) {
            throw new ConfigurationException('Required options not defined: openIDConnectMetadataUrl');
        }

        if (empty($collaborators['jwt'])) {
            $collaborators['jwt'] = new RequestFactory();
        }
        $this->setRequestFactory($collaborators['jwt']);

        $this->setAllowHttp((bool) ($options['allowHttp'] ?? false));
        $this->setOpenIDConnectMetadataUrl($options['openIDConnectMetadataUrl']);
    }

    public function getGuarded(): array
    {
        // Prevent these option from being set by direct access by the
        // parent constructor.
        return ['cacheItemPool', 'cacheDuration', 'openIDConnectMetadataUrl', 'leeway', 'allowHttp'];
    }

    /**
     * @throws BadUrlException
     * @throws CacheException
     * @throws HttpException
     * @throws IllegalSchemeException
     * @throws JsonException
     * @throws MetadataException
     */
    public function getBaseAuthorizationUrl(): string
    {
        return $this->getSecureEndpoint('authorization_endpoint');
    }

    /**
     * @throws OpenIdConnectExceptionInterface
     */
    public function getAuthorizationUrl(array $options = []): string
    {
        // Enforce use of state parameter
        // @see https://docs.microsoft.com/en-us/azure/active-directory-b2c/openid-connect#send-authentication-requests
        if (empty($options['state'])) {
            throw new MissingParameterException('Required parameter "state" missing');
        }

        // Enforce use of required nonce parameter
        // @see https://docs.microsoft.com/en-us/azure/active-directory-b2c/openid-connect#send-authentication-requests
        if (empty($options['nonce'])) {
            throw new MissingParameterException('Required parameter "nonce" missing');
        }

        // Add default response_type and response_mode. The `scope` default is
        // supplied by getDefaultScopes() via league's
        // getAuthorizationParameters(), so it is not repeated here.
        return parent::getAuthorizationUrl($options + [
            'response_type' => 'id_token',
            'response_mode' => 'query',
        ]);
    }

    /**
     * Get the end session endpoint from the metadata url.
     *
     * @see https://docs.microsoft.com/en-us/azure/active-directory-b2c/openid-connect#send-a-sign-out-request
     * @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
     *
     * @param string|null $postLogoutRedirectUri The URL that the user should be redirected to after successful sign out
     * @param string|null $state                 If a state parameter is included in the request, the same value should appear in the response. The application should verify that the state values in the request and response are identical.
     * @param string|null $idToken               The id token
     *
     * @return string The Url to redirect the client to for session logout
     *
     * @throws BadUrlException
     * @throws CacheException
     * @throws HttpException
     * @throws IllegalSchemeException
     * @throws JsonException
     * @throws MetadataException
     */
    public function getEndSessionUrl(?string $postLogoutRedirectUri = null, ?string $state = null, ?string $idToken = null): string
    {
        $url = $this->getSecureEndpoint('end_session_endpoint');

        $params = [];
        if ($postLogoutRedirectUri) {
            $params[self::POST_LOGOUT_REDIRECT_URI] = $postLogoutRedirectUri;
        }

        if ($state) {
            $params[self::STATE] = $state;
        }

        if ($idToken) {
            $params[self::ID_TOKEN_HINT] = $idToken;
        }

        if (!empty($params)) {
            $glue = null === parse_url($url, PHP_URL_QUERY) ? '?' : '&';
            $url .= $glue.$this->buildQueryString($params);
        }

        return $url;
    }

    /**
     * Do any required verification of the id token and return an array of decoded claims.
     *
     * The "exp" (expiration) claim is validated by firebase/php-jwt during
     * JWT::decode(), using the configured leeway for clock skew tolerance. It is
     * only validated when present, so this method additionally asserts that
     * "exp" and "iat" exist — both REQUIRED by OIDC Core §2 — which is what
     * stops a token without "exp" from never expiring.
     *
     * "aud", "iss" and "nonce" are checked here. The nonce comparison is
     * constant-time: it is the only claim compared against a value the caller
     * holds, so a timing signal would leak that secret.
     *
     * Note: JWT::$leeway is a static property, so in environments with multiple
     * OpenIdConfigurationProvider instances (e.g. multi-tenant setups in long-running
     * processes), the leeway value set by the last provider to call validateIdToken()
     * will apply globally until overwritten.
     *
     * @param string $idToken Raw id token
     * @param string $nonce   Nonce
     *
     * @return object The JWT's payload as a PHP object
     *
     * @throws CacheException
     * @throws ClaimsException
     * @throws DecodeException
     * @throws HttpException
     * @throws JsonException
     * @throws JwksException
     * @throws MetadataException
     * @throws ValidationException
     */
    public function validateIdToken(string $idToken, string $nonce): object
    {
        try {
            $keys = $this->getJwtVerificationKeys();
            // NB: JWT::$leeway is a static property shared across all instances.
            // Always set it immediately before decode to ensure the correct value.
            JWT::$leeway = $this->leeway;
            $claims = JWT::decode($idToken, $keys);

            // "exp" and "iat" are REQUIRED by OIDC Core §2, but
            // firebase/php-jwt only validates them when they are present — a
            // token without "exp" never expires. Presence is asserted here so
            // the decode above is what enforces the deadline.
            self::requireNumericClaim($claims, 'exp');
            self::requireNumericClaim($claims, 'iat');

            // "aud" may be an array of strings or a single string
            // (cf. https://openid.net/specs/openid-connect-core-1_0.html#IDToken).
            // Non-string entries are dropped: they cannot match a string client
            // id under strict comparison, and would turn the message below into
            // an "Array to string conversion".
            $audiences = array_filter((array) $claims->aud, 'is_string');
            if (!in_array($this->clientId, $audiences, true)) {
                throw new ClaimsException('ID token has incorrect audience(s): '.implode(', ', $audiences));
            }

            $issuer = self::requireStringClaim($claims, 'iss');
            if ($issuer !== $this->getConfiguration('issuer')) {
                throw new ClaimsException('ID token has incorrect issuer: '.$issuer);
            }

            // Compared in constant time: the nonce is the one claim checked
            // against a value the caller holds, so a timing signal here would
            // leak that secret rather than a public identifier.
            $claimedNonce = self::requireStringClaim($claims, 'nonce');
            if (!hash_equals($nonce, $claimedNonce)) {
                throw new ClaimsException('ID token has incorrect nonce: '.$claimedNonce);
            }

            return $claims;
        } catch (\UnexpectedValueException $e) {
            throw new ValidationException('ID token validation failed: '.$e->getMessage(), 0, $e);
        }
    }

    /**
     * Assert that a claim is present and numeric.
     *
     * Presence only — the value itself is validated by firebase/php-jwt during
     * the decode, using the configured leeway.
     *
     * @throws ClaimsException
     */
    private static function requireNumericClaim(object $claims, string $name): void
    {
        if (!isset($claims->{$name}) || !is_numeric($claims->{$name})) {
            throw new ClaimsException(sprintf('ID token missing required numeric "%s" claim (OIDC Core §2)', $name));
        }
    }

    /**
     * Assert that a claim is present and a non-empty string, and return it.
     *
     * Returning the narrowed value keeps the callers from re-reading an
     * arbitrarily typed property, which is what made string concatenation in
     * their exception messages unsafe.
     *
     * @throws ClaimsException
     */
    private static function requireStringClaim(object $claims, string $name): string
    {
        $value = $claims->{$name} ?? null;

        if (!is_string($value) || '' === $value) {
            throw new ClaimsException(sprintf('ID token missing required string "%s" claim', $name));
        }

        return $value;
    }

    /**
     * Get id token from code.
     *
     * @param string $code The code
     *
     * @return string The ID token
     *
     * @throws OpenIdConnectExceptionInterface
     */
    public function getIdToken(string $code): string
    {
        try {
            $endpoint = $this->getSecureEndpoint('token_endpoint');
            $response = $this->getHttpClient()->request('POST', $endpoint, [
                'form_params' => [
                    'client_id' => $this->clientId,
                    'client_secret' => $this->clientSecret,
                    'redirect_uri' => $this->redirectUri,
                    'grant_type' => 'authorization_code',
                    'code' => $code,
                ],
            ]);

            $payload = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);

            if (!is_array($payload) || !is_string($payload['id_token'] ?? null)) {
                throw new CodeException('Token endpoint response missing string "id_token"');
            }

            return $payload['id_token'];
        } catch (ClientExceptionInterface|\JsonException $e) {
            // Narrow boundary: ClientExceptionInterface from Guzzle,
            // \JsonException from json_decode. This method issues the token
            // request directly rather than through league's getParsedResponse(),
            // so checkResponse() — and with it IdentityProviderException — is
            // never on this path. Other failures (e.g. CacheException from
            // getSecureEndpoint) propagate as their own concrete
            // OpenIdConnectExceptionInterface subtypes.
            throw new CodeException('Get ID token failed: '.$e->getMessage(), 0, $e);
        }
    }

    /**
     * Generates a new random string to use as the state parameter in an
     * authorization flow.
     *
     * @param int $length Length of the random string to be generated
     *
     * @return string The generated state
     */
    public function generateState(int $length = 32): string
    {
        $this->state = parent::getRandomState($length);

        return $this->state;
    }

    /**
     * Generates a new random string to use as the nonce parameter in an
     * authorization flow.
     *
     * @param int $length Length of the random string to be generated
     *
     * @return string The generated nonce
     */
    public function generateNonce(int $length = 32): string
    {
        return parent::getRandomState($length);
    }

    /**
     * @throws BadUrlException
     * @throws CacheException
     * @throws HttpException
     * @throws IllegalSchemeException
     * @throws JsonException
     * @throws MetadataException
     */
    public function getBaseAccessTokenUrl(array $params): string
    {
        return $this->getSecureEndpoint('token_endpoint');
    }

    /**
     * @throws BadUrlException
     * @throws CacheException
     * @throws HttpException
     * @throws IllegalSchemeException
     * @throws JsonException
     * @throws MetadataException
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token): string
    {
        return $this->getSecureEndpoint('userinfo_endpoint');
    }

    /**
     * @see https://docs.microsoft.com/en-us/azure/active-directory-b2c/openid-connect#send-authentication-requests
     */
    public function getDefaultScopes(): array
    {
        return ['openid'];
    }

    protected function checkResponse(ResponseInterface $response, $data): void
    {
        $error = null;
        if (!empty($data[$this->responseError])) {
            $error = $data[$this->responseError];
            if (!is_string($error)) {
                $error = var_export($error, true);
            }
        }
        if ($error || $response->getStatusCode() >= 400) {
            $error = $error ?? (string) $response->getStatusCode();
            throw new IdentityProviderException($error, 0, $data);
        }
    }

    protected function createResourceOwner(array $response, AccessToken $token): ResourceOwnerInterface
    {
        return new GenericResourceOwner($response, $this->responseResourceOwnerId);
    }

    /**
     * Get JWT verification keys from Azure Active Directory.
     *
     * @return array<string, Key> Array of keys indexed by JWK `kid`
     *
     * @throws OpenIdConnectExceptionInterface
     */
    private function getJwtVerificationKeys(): array
    {
        $jwks = $this->getJwksDocument();

        if (!isset($jwks['keys']) || !is_array($jwks['keys'])) {
            throw new JwksException('JWKS payload missing array "keys" property (RFC 7517 §5)');
        }

        $keys = [];

        foreach ($jwks['keys'] as $key) {
            if (!is_array($key)) {
                throw new JwksException('JWK entry is not a JSON object');
            }
            if (!is_string($key['kid'] ?? null)) {
                throw new JwksException('JWK entry missing string "kid" (RFC 7517 §4.5)');
            }
            $kid = $key['kid'];
            if (!is_string($key['kty'] ?? null)) {
                throw new JwksException('JWK entry missing string "kty" for key id: '.$kid);
            }
            if ('RSA' !== $key['kty']) {
                throw new JwksException('Unsupported key data for key id: '.$kid);
            }
            if (!is_string($key['e'] ?? null) || !is_string($key['n'] ?? null)) {
                throw new JwksException('JWK RSA entry missing string "e"/"n" for key id: '.$kid);
            }

            // These guards stay in front of JWK::parseKey() rather than
            // delegating to it: firebase/php-jwt accepts a non-string, empty or
            // undecodable exponent and builds a key from it, so dropping them
            // would undo the strict JWKS validation 5.0.0 introduced. Emptiness
            // is checked on the decoded bytes because "", " " and "\n" all
            // base64-decode to zero bytes.
            $e = self::base64urlDecode($key['e']);
            $n = self::base64urlDecode($key['n']);
            if ('' === $e || '' === $n) {
                throw new JwksException('JWK RSA entry has empty "e"/"n" for key id: '.$kid);
            }

            try {
                $parsed = JWK::parseKey($key, self::SIGNING_ALGORITHM);
            } catch (\UnexpectedValueException|\InvalidArgumentException|\DomainException $exception) {
                throw new JwksException(sprintf('JWK entry for key id %s is not a usable key: %s', $kid, $exception->getMessage()), 0, $exception);
            }

            // parseKey() is typed `?Key` because it returns null for key types
            // it does not handle — all of which the "RSA" check above has
            // already rejected, so this cannot be null here.
            assert($parsed instanceof Key);

            $keys[$kid] = $parsed;
        }

        return $keys;
    }

    /**
     * Get the IdP's JWKS document, cached for `cacheDuration` seconds.
     *
     * The document is cached rather than the `Key` objects built from it:
     * `JWK::parseKey()` returns keys wrapping an `OpenSSLAsymmetricKey`, which
     * PHP refuses to serialize, so they cannot go into a PSR-6 pool. Parsing on
     * each call costs microseconds and the network fetch is still cached.
     *
     * @return array The JWKS document
     *
     * @throws BadUrlException
     * @throws CacheException
     * @throws HttpException
     * @throws IllegalSchemeException
     * @throws JsonException
     * @throws MetadataException
     */
    private function getJwksDocument(): array
    {
        // Deliberately not the 5.0 cache key: entries written by 5.0 hold
        // serialized `Key` objects, and reading those as a JWKS document would
        // fail until they expired.
        $cacheKey = $this->getCacheKey('jwks-document');

        try {
            assert($this->cacheItemPool instanceof CacheItemPoolInterface);
            $item = $this->cacheItemPool->getItem($cacheKey);

            if ($item->isHit()) {
                return (array) $item->get();
            }

            $jwks = $this->fetchJsonResource($this->getSecureEndpoint('jwks_uri'));

            $item->set($jwks);
            $item->expiresAfter($this->cacheDuration);
            $this->cacheItemPool->save($item);

            return $jwks;
        } catch (InvalidArgumentException $e) {
            throw new CacheException($e->getMessage(), 0, $e);
        }
    }

    /**
     * Decode base 64 url.
     *
     * @throws DecodeException
     */
    private static function base64urlDecode(string $input): string
    {
        $decoded = base64_decode(strtr($input, '-_', '+/'), true);

        if (false === $decoded) {
            throw new DecodeException('Error url decoding input '.$input);
        }

        return $decoded;
    }

    /**
     * Fetch remote json resource.
     *
     * Both resources this fetches — the discovery document and the JWKS — are
     * capped at MAX_JSON_RESOURCE_BYTES. The declared body size is checked first
     * where the response reports one, and the retrieved content unconditionally,
     * because a chunked response reports no size.
     *
     * The cap bounds what gets decoded and written to the cache, not peak
     * memory: Guzzle has already buffered the body by the time it is visible
     * here. Bounding the transfer itself would mean a streaming read against a
     * `stream => true` request, which is a larger change than the exposure
     * warrants for a document fetched from a configured host over TLS.
     *
     * @return array Json decoded to array
     *
     * @throws HttpException
     * @throws JsonException
     */
    private function fetchJsonResource(string $resourceUrl): array
    {
        try {
            $response = $this->getHttpClient()->request('GET', $resourceUrl);

            if (200 !== $response->getStatusCode()) {
                throw new HttpException('Cannot access json resource: '.$resourceUrl);
            }

            $body = $response->getBody();
            $declaredSize = $body->getSize();

            if (null !== $declaredSize && $declaredSize > self::MAX_JSON_RESOURCE_BYTES) {
                throw new HttpException($this->oversizedResourceMessage($resourceUrl, $declaredSize));
            }

            $content = $body->getContents();

            if (strlen($content) > self::MAX_JSON_RESOURCE_BYTES) {
                throw new HttpException($this->oversizedResourceMessage($resourceUrl, strlen($content)));
            }

            /** @var array $resource */
            $resource = json_decode($content, true, 512, JSON_THROW_ON_ERROR);

            return $resource;
        } catch (ClientExceptionInterface $e) {
            throw new HttpException($e->getMessage(), 0, $e);
        } catch (\JsonException $e) {
            throw new JsonException($e->getMessage(), 0, $e);
        }
    }

    private function oversizedResourceMessage(string $resourceUrl, int $size): string
    {
        return sprintf(
            'Json resource is larger than the %d byte limit (%d bytes): %s',
            self::MAX_JSON_RESOURCE_BYTES,
            $size,
            $resourceUrl,
        );
    }

    /**
     * Get Configuration option for key.
     *
     * @param string $key The configuration key
     *
     * @return string The configuration value for the given key
     *
     * @throws CacheException
     * @throws HttpException
     * @throws JsonException
     * @throws MetadataException
     */
    private function getConfiguration(string $key): string
    {
        $cacheKey = $this->getCacheKey('configuration');

        try {
            assert($this->cacheItemPool instanceof CacheItemPoolInterface);
            $item = $this->cacheItemPool->getItem($cacheKey);
            if ($item->isHit()) {
                $configuration = (array) $item->get();
            } else {
                $configuration = $this->fetchJsonResource($this->openIDConnectMetadataUrl);
                $item->set($configuration);
                $item->expiresAfter($this->cacheDuration);
                $this->cacheItemPool->save($item);
            }

            if (!isset($configuration[$key])) {
                throw new MetadataException('OIDC discovery document missing required key: '.$key);
            }
            if (!is_string($configuration[$key])) {
                throw new MetadataException(sprintf('OIDC discovery document value for "%s" is not a string (got %s)', $key, get_debug_type($configuration[$key])));
            }

            return $configuration[$key];
        } catch (InvalidArgumentException $e) {
            throw new CacheException($e->getMessage(), 0, $e);
        }
    }

    /**
     * Get an endpoint URL from the discovery document, enforcing the scheme policy.
     *
     * `allowHttp` governs every URL this client talks to, not just the metadata
     * URL it was configured with. A tampered or misconfigured discovery
     * document announcing `http://…/token` would otherwise get the client
     * secret posted in plaintext.
     *
     * @param string $key The discovery document key
     *
     * @return string The endpoint URL for the given key
     *
     * @throws BadUrlException
     * @throws CacheException
     * @throws HttpException
     * @throws IllegalSchemeException
     * @throws JsonException
     * @throws MetadataException
     */
    private function getSecureEndpoint(string $key): string
    {
        $url = $this->getConfiguration($key);

        $this->assertSecureUrl($url, sprintf('OIDC discovery document "%s"', $key));

        return $url;
    }

    private function getCacheKey(string $name): string
    {
        return implode('||', [
            self::CACHE_KEY_PREFIX,
            hash('sha1', $this->openIDConnectMetadataUrl),
            $name,
        ]);
    }

    /**
     * Set the provider cache item pool.
     */
    private function setCacheItemPool(CacheItemPoolInterface $cacheItemPool): void
    {
        $this->cacheItemPool = $cacheItemPool;
    }

    /**
     * Set the provider cache duration.
     *
     * @param int $cacheDuration The cache duration in seconds
     *
     * @throws NegativeCacheDurationException
     */
    private function setCacheDuration(int $cacheDuration): void
    {
        if ($cacheDuration < 0) {
            throw new NegativeCacheDurationException('Cache Duration has to be a positive integer');
        }
        $this->cacheDuration = $cacheDuration;
    }

    /**
     * Set the leeway to allow for clock skew between hosting server and provider.
     *
     * @param int $leeway The leeway in seconds. Must be positive
     *
     * @throws NegativeLeewayException
     */
    private function setLeeway(int $leeway): void
    {
        if ($leeway < 0) {
            throw new NegativeLeewayException('Leeway has to be a positive integer');
        }
        $this->leeway = $leeway;
    }

    /**
     * Set allow HTTP.
     *
     * @param bool $allowHttp Whether to allow HTTP
     */
    private function setAllowHttp(bool $allowHttp): void
    {
        $this->allowHttp = $allowHttp;
    }

    /**
     * Set the OpenID Connect Metadata Url.
     *
     * @throws OpenIdConnectExceptionInterface
     */
    private function setOpenIDConnectMetadataUrl(string $url): void
    {
        $this->assertSecureUrl($url, 'OpenIDConnectMetadataUrl');

        $this->openIDConnectMetadataUrl = $url;
    }

    /**
     * Assert that a URL is one this client is willing to talk to.
     *
     * @param string $url     The URL to check
     * @param string $subject What the URL is, for the exception message
     *
     * @throws BadUrlException        If the URL has no parsable scheme
     * @throws IllegalSchemeException If the scheme is not https and `allowHttp` is false
     */
    private function assertSecureUrl(string $url, string $subject): void
    {
        $scheme = parse_url($url, PHP_URL_SCHEME);

        if (!is_string($scheme)) {
            throw new BadUrlException($subject.' is invalid: '.$url);
        }

        // Schemes are case-insensitive (RFC 3986 §3.1), so "HTTPS://" is valid.
        if (!$this->allowHttp && 'https' !== strtolower($scheme)) {
            throw new IllegalSchemeException($subject.' must use https: '.$url);
        }
    }
}
