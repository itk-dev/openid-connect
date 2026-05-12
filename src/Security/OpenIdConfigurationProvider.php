<?php

declare(strict_types=1);

namespace ItkDev\OpenIdConnect\Security;

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
use ItkDev\OpenIdConnect\Exception\KeyException;
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
use RobRichards\XMLSecLibs\XMLSecurityKey;

/**
 * Class OpenIdConfigurationProvider.
 *
 * @see https://github.com/cirrusidentity/simplesamlphp-module-authoauth2/blob/master/src/Providers/OpenIDConnectProvider.php
 */
class OpenIdConfigurationProvider extends AbstractProvider
{
    private const string CACHE_KEY_PREFIX = 'itk-openid-connect-configuration-';

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

        if (array_key_exists('leeway', $options) && is_int($options['leeway'])) {
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
     * @throws CacheException
     * @throws HttpException
     * @throws JsonException
     * @throws MetadataException
     */
    public function getBaseAuthorizationUrl(): string
    {
        return $this->getConfiguration('authorization_endpoint');
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

        // Add default options scope, response_type and response_mode
        return parent::getAuthorizationUrl($options + [
            'scope' => 'openid',
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
     * @param string|null $postLogoutRedirectUri
     *                                           The URL that the user should be redirected to after successful sign out
     * @param string|null $state
     *                                           If a state parameter is included in the request, the same value should appear in the response. The application should verify that the state values in the request and response are identical.
     * @param string|null $idToken
     *                                           The id token
     *
     * @return string
     *                The Url to redirect the client to for session logout
     *
     * @throws CacheException
     * @throws HttpException
     * @throws JsonException
     * @throws MetadataException
     */
    public function getEndSessionUrl(?string $postLogoutRedirectUri = null, ?string $state = null, ?string $idToken = null): string
    {
        $url = $this->getConfiguration('end_session_endpoint');

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
     * Note: The "exp" (expiration) claim is validated by firebase/php-jwt during
     * JWT::decode(), using the configured leeway for clock skew tolerance.
     *
     * Note: JWT::$leeway is a static property, so in environments with multiple
     * OpenIdConfigurationProvider instances (e.g. multi-tenant setups in long-running
     * processes), the leeway value set by the last provider to call validateIdToken()
     * will apply globally until overwritten.
     *
     * @param string $idToken
     *                        Raw id token
     * @param string $nonce
     *                        Nonce
     *
     * @return object
     *                The JWT's payload as a PHP object
     *
     * @throws CacheException
     * @throws ClaimsException
     * @throws DecodeException
     * @throws HttpException
     * @throws JsonException
     * @throws KeyException
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
            // "aud" may be an array of strings or a single string
            // (cf. https://openid.net/specs/openid-connect-core-1_0.html#IDToken).
            $audiences = (array) $claims->aud;
            if (!in_array($this->clientId, $audiences)) {
                throw new ClaimsException('ID token has incorrect audience(s): '.implode(', ', $audiences));
            }
            if ($claims->iss !== $this->getConfiguration('issuer')) {
                throw new ClaimsException('ID token has incorrect issuer: '.$claims->iss);
            }
            if ($claims->nonce !== $nonce) {
                throw new ClaimsException('ID token has incorrect nonce: '.$claims->nonce);
            }

            return $claims;
        } catch (\UnexpectedValueException $e) {
            throw new ValidationException('ID token validation failed: '.$e->getMessage(), 0, $e);
        }
    }

    /**
     * Get id token from code.
     *
     * @param string $code
     *                     The code
     *
     * @return string
     *                The ID token
     *
     * @throws OpenIdConnectExceptionInterface
     */
    public function getIdToken(string $code): string
    {
        try {
            $endpoint = $this->getConfiguration('token_endpoint');
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

            return $payload['id_token'];
        } catch (IdentityProviderException|ClientExceptionInterface|\JsonException $e) {
            // Narrow boundary: IdentityProviderException from league's checkResponse,
            // ClientExceptionInterface from Guzzle, \JsonException from json_decode.
            // Other failures (e.g. CacheException from getConfiguration) propagate
            // as their own concrete OpenIdConnectExceptionInterface subtypes.
            throw new CodeException('Get ID token failed: '.$e->getMessage(), 0, $e);
        }
    }

    /**
     * Generates a new random string to use as the state parameter in an
     * authorization flow.
     *
     * @param int $length
     *                    Length of the random string to be generated
     *
     * @return string
     *                The generated state
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
     * @param int $length
     *                    Length of the random string to be generated
     *
     * @return string
     *                The generated nonce
     */
    public function generateNonce(int $length = 32): string
    {
        return parent::getRandomState($length);
    }

    public function getBaseAccessTokenUrl(array $params): string
    {
        return $this->getConfiguration('token_endpoint');
    }

    public function getResourceOwnerDetailsUrl(AccessToken $token): string
    {
        return $this->getConfiguration('userinfo_endpoint');
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
     * @return array
     *               Array of keys
     *
     * @throws OpenIdConnectExceptionInterface
     */
    private function getJwtVerificationKeys(): array
    {
        $cacheKey = $this->getCacheKey('jwks');

        $keys = [];

        try {
            assert($this->cacheItemPool instanceof CacheItemPoolInterface);
            $item = $this->cacheItemPool->getItem($cacheKey);

            if ($item->isHit()) {
                $keys = (array) $item->get();
            } else {
                $keysUri = $this->getConfiguration('jwks_uri');
                $jwks = $this->fetchJsonResource($keysUri);

                foreach ($jwks['keys'] as $key) {
                    if (!is_string($key['kid'] ?? null)) {
                        throw new KeyException('JWK entry missing string "kid" (RFC 7517 §4.5)');
                    }
                    $kid = $key['kid'];
                    if ('RSA' === $key['kty']) {
                        $e = self::base64urlDecode($key['e']);
                        $n = self::base64urlDecode($key['n']);
                        $publicKey = XMLSecurityKey::convertRSA($n, $e);
                        $keys[$kid] = new Key($publicKey, 'RS256');
                    } else {
                        throw new KeyException('Unsupported key data for key id: '.$kid);
                    }
                }

                $item->set($keys);
                $item->expiresAfter($this->cacheDuration);
                $this->cacheItemPool->save($item);
            }
        } catch (InvalidArgumentException $e) {
            throw new CacheException($e->getMessage(), 0, $e);
        }

        return $keys;
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
     * @return array
     *               Json decoded to array
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

            $content = $response->getBody()->getContents();

            /** @var array $resource */
            $resource = json_decode($content, true, 512, JSON_THROW_ON_ERROR);

            return $resource;
        } catch (ClientExceptionInterface $e) {
            throw new HttpException($e->getMessage(), 0, $e);
        } catch (\JsonException $e) {
            throw new JsonException($e->getMessage(), 0, $e);
        }
    }

    /**
     * Get Configuration option for key.
     *
     * @param string $key
     *                    The configuration key
     *
     * @return string
     *                The configuration value for the given key
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
     * @param int $cacheDuration
     *                           The cache duration in seconds
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
     * @param int $leeway
     *                    The leeway in seconds. Must be positive
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
     * @param bool $allowHttp
     *                        Whether to allow HTTP
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
        $scheme = parse_url($url, PHP_URL_SCHEME);

        if (null === $scheme) {
            throw new BadUrlException('OpenIDConnectMetadataUrl is invalid: '.$url);
        }

        if (!$this->allowHttp && 'https' !== $scheme) {
            throw new IllegalSchemeException('OpenIDConnectMetadataUrl must use https: '.$url);
        }

        $this->openIDConnectMetadataUrl = $url;
    }
}
