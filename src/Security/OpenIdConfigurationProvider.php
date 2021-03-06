<?php

declare(strict_types=1);

namespace ItkDev\OpenIdConnect\Security;

use Firebase\JWT\JWT;
use GuzzleHttp\Exception\GuzzleException;
use ItkDev\OpenIdConnect\Exception\CacheException;
use ItkDev\OpenIdConnect\Exception\ClaimsException;
use ItkDev\OpenIdConnect\Exception\DecodeException;
use ItkDev\OpenIdConnect\Exception\HttpException;
use ItkDev\OpenIdConnect\Exception\IllegalSchemeException;
use ItkDev\OpenIdConnect\Exception\NegativeLeewayException;
use ItkDev\OpenIdConnect\Exception\ItkOpenIdConnectException;
use ItkDev\OpenIdConnect\Exception\JsonException;
use ItkDev\OpenIdConnect\Exception\KeyException;
use ItkDev\OpenIdConnect\Exception\BadUrlException;
use ItkDev\OpenIdConnect\Exception\MissingParameterException;
use ItkDev\OpenIdConnect\Exception\ValidationException;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericResourceOwner;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\RequestFactory;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Cache\InvalidArgumentException;
use Psr\Http\Message\ResponseInterface;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/**
 * Class OpenIdConfigurationProvider.
 *
 * @see https://github.com/cirrusidentity/simplesamlphp-module-authoauth2/blob/master/lib/Providers/OpenIDConnectProvider.php
 */
class OpenIdConfigurationProvider extends AbstractProvider
{
    private const CACHE_KEY = 'itk-openid-connect-configuration-';

    /**
     * @var string
     */
    protected $openIDConnectMetadataUrl;

    /**
     * @var CacheItemPoolInterface
     */
    private $cacheItemPool;

    /**
     * @var int
     */
    private $cacheDuration = 86400;

    /**
     * @var string
     */
    private $responseResourceOwnerId = 'id';

    /**
     * OpenIdConfigurationProvider constructor.
     *
     * @param array $options
     * @param array $collaborators
     *
     * @throws ItkOpenIdConnectException
     *
     * @psalm-suppress MixedArgument
     */
    public function __construct(array $options = [], array $collaborators = [])
    {
        parent::__construct($options, $collaborators);

        if (!array_key_exists('cacheItemPool', $options)) {
            throw new \InvalidArgumentException(
                'Required options not defined: cacheItemPool'
            );
        }
        $this->setCacheItemPool($options['cacheItemPool']);

        if (array_key_exists('cacheDuration', $options)) {
            $this->setCacheDuration($options['cacheDuration']);
        }

        if (!array_key_exists('openIDConnectMetadataUrl', $options)) {
            throw new \InvalidArgumentException(
                'Required options not defined: openIDConnectMetadataUrl'
            );
        }

        if (empty($collaborators['jwt'])) {
            $collaborators['jwt'] = new RequestFactory();
        }
        $this->setRequestFactory($collaborators['jwt']);

        $this->setOpenIDConnectMetadataUrl($options['openIDConnectMetadataUrl']);
    }

    /**
     * Set the provider cache item pool
     *
     * @param CacheItemPoolInterface $cacheItemPool
     */
    public function setCacheItemPool(CacheItemPoolInterface $cacheItemPool): void
    {
        $this->cacheItemPool = $cacheItemPool;
    }

    /**
     * Set the provider cache duration
     *
     * @param int $cacheDuration
     *   The cache duration in seconds
     */
    public function setCacheDuration(int $cacheDuration): void
    {
        $this->cacheDuration = $cacheDuration;
    }

    /**
     * Set the OpenID Connect Metadata Url
     *
     * @param string $url
     *
     * @throws ItkOpenIdConnectException
     */
    public function setOpenIDConnectMetadataUrl(string $url): void
    {
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            throw new BadUrlException('OpenIDConnectMetadataUrl is invalid: ' . $url);
        }

        if (parse_url($url, PHP_URL_SCHEME) !== 'https') {
            throw new IllegalSchemeException('OpenIDConnectMetadataUrl must use https: ' . $url);
        }

        $this->openIDConnectMetadataUrl = $url;
    }

    /**
     * {@inheritdoc}
     */
    public function getGuarded()
    {
        // Prevent these option from being set by direct access by the
        // parent constructor.
        return ['cacheItemPool', 'cacheDuration', 'openIDConnectMetadataUrl'];
    }

    /**
     * {@inheritdoc}
     */
    public function getBaseAuthorizationUrl(): string
    {
        return $this->getConfiguration('authorization_endpoint');
    }

    /**
     * {@inheritdoc}
     *
     * @throws ItkOpenIdConnectException
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
     * Do any required verification of the id token and return an array of decoded claims
     *
     * @param string $idToken
     *   Raw id token
     *
     * @param string $nonce
     *   Nonce
     *
     * @param int $leeway
     *   Leeway set in seconds. Defaults to 0 and must be positive
     *
     * @return object
     *   The JWT's payload as a PHP object
     *
     * @throws ItkOpenIdConnectException
     */
    public function validateIdToken(string $idToken, string $nonce, int $leeway = 0): object
    {
        if ($leeway < 0) {
            throw new NegativeLeewayException('Leeway has to be a positive integer');
        }

        try {
            $keys = $this->getJwtVerificationKeys();
            JWT::$leeway = $leeway;
            $claims = JWT::decode($idToken, $keys, ['RS256']);
            if ($claims->aud !== $this->clientId) {
                throw new ClaimsException('ID token has incorrect audience: ' . $claims->aud);
            }
            if ($claims->iss !== $this->getConfiguration('issuer')) {
                throw new ClaimsException('ID token has incorrect issuer: ' . $claims->iss);
            }
            if ($claims->nonce !== $nonce) {
                throw new ClaimsException('ID token has incorrect nonce: ' . $claims->nonce);
            }

            return $claims;
        } catch (\UnexpectedValueException $e) {
            throw new ValidationException('ID token validation failed: ' . $e->getMessage());
        }
    }

    /**
     * Generates a new random string to use as the state parameter in an
     * authorization flow.
     *
     * @param  int $length
     *   Length of the random string to be generated.
     * @return string
     *   The generated state
     */
    public function generateState(int $length = 32)
    {
        $this->state = parent::getRandomState($length);

        return $this->state;
    }

    /**
     * Generates a new random string to use as the nonce parameter in an
     * authorization flow.
     *
     * @param  int $length
     *   Length of the random string to be generated.
     * @return string
     *   The generated nonce
     */
    public function generateNonce(int $length = 32)
    {
        return parent::getRandomState($length);
    }

    /**
     * {@inheritdoc}
     */
    public function getBaseAccessTokenUrl(array $params): string
    {
        return $this->getConfiguration('token_endpoint');
    }

    /**
     * {@inheritdoc}
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token): string
    {
        return $this->getConfiguration('userinfo_endpoint');
    }

    /**
     * @inheritdoc
     *
     * @see https://docs.microsoft.com/en-us/azure/active-directory-b2c/openid-connect#send-authentication-requests
     */
    public function getDefaultScopes(): array
    {
        return ['openid'];
    }

    /**
     * {@inheritdoc}
     */
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

    /**
     * @inheritdoc
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new GenericResourceOwner($response, $this->responseResourceOwnerId);
    }

    /**
     * Get JWT verification keys from Azure Active Directory.
     *
     * @return array
     *   Array of keys
     *
     * @throws ItkOpenIdConnectException
     *
     * @psalm-suppress MixedOperand
     * @psalm-suppress InvalidCatch
     */
    private function getJwtVerificationKeys(): array
    {
        $cacheKey = self::CACHE_KEY . 'jwks';
        $keys = [];

        try {
            $item = $this->cacheItemPool->getItem($cacheKey);

            if ($item->isHit()) {
                $keys = (array) $item->get();
            } else {
                $keysUri = $this->getConfiguration('jwks_uri');
                $jwks = $this->fetchJsonResource($keysUri);

                foreach ($jwks['keys'] as $key) {
                    $kid = (string) $key['kid'];
                    if ($key['kty'] === 'RSA') {
                        $e = self::base64urlDecode($key['e']);
                        $n = self::base64urlDecode($key['n']);
                        $keys[$kid] = XMLSecurityKey::convertRSA($n, $e);
                    } else {
                        throw new KeyException('Unsupported key data for key id: ' . $kid);
                    }
                }

                $item->set($keys);
                $item->expiresAfter($this->cacheDuration);
            }
        } catch (InvalidArgumentException $e) {
            throw new CacheException($e->getMessage());
        }

        return $keys;
    }

    /**
     * Decode base 64 url
     *
     * @param string $input
     *
     * @return string
     *
     * @throws DecodeException
     */
    private static function base64urlDecode(string $input): string
    {
        $decoded = base64_decode(strtr($input, '-_', '+/'));

        if ($decoded === false) {
            throw new DecodeException('Error url decoding input ' . $input);
        }
        return $decoded;
    }

    /**
     * Fetch remote json resource
     *
     * @param string $resourceUrl
     *
     * @return array
     *   Json decoded to array
     *
     * @throws HttpException
     * @throws JsonException
     */
    private function fetchJsonResource(string $resourceUrl): array
    {
        try {
            $response = $this->getHttpClient()->request('GET', $resourceUrl);

            if (200 !== $response->getStatusCode()) {
                throw new HttpException('Cannot access json resource: ' .  $resourceUrl);
            }

            $content = $response->getBody()->getContents();

            /** @var array $resource */
            $resource = json_decode($content, true, 512, JSON_THROW_ON_ERROR);

            return $resource;
        } catch (GuzzleException $e) {
            throw new HttpException($e->getMessage());
        } catch (\JsonException $e) {
            throw new JsonException($e->getMessage());
        }
    }

    /**
     * Get Configuration option for key.
     *
     * @param string $key
     *  The configuration key
     *
     * @return string
     *   The configuration value for the given key
     *
     * @throws CacheException
     * @throws HttpException
     * @throws JsonException
     *
     * @psalm-suppress InvalidCatch
     */
    private function getConfiguration(string $key): string
    {
        $cacheKey = self::CACHE_KEY . 'configuration';

        try {
            $item = $this->cacheItemPool->getItem($cacheKey);
            if ($item->isHit()) {
                $configuration = (array) $item->get();
            } else {
                $configuration = $this->fetchJsonResource($this->openIDConnectMetadataUrl);
                $item->set($configuration);
                $item->expiresAfter($this->cacheDuration);
                $this->cacheItemPool->save($item);
            }

            if (isset($configuration[$key])) {
                $value = (string) $configuration[$key];
            } else {
                throw new CacheException('Required config key not defined: ' . $key);
            }

            return $value;
        } catch (InvalidArgumentException $e) {
            throw new CacheException($e->getMessage());
        }
    }
}
