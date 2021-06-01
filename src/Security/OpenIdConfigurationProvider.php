<?php

declare(strict_types=1);

namespace ItkDev\OpenIdConnect\Security;

use Firebase\JWT\JWT;
use GuzzleHttp\Exception\GuzzleException;
use ItkDev\OpenIdConnect\Exception\ItkOpenIdConnectException;
use JsonException;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericResourceOwner;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\RequestFactory;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Cache\InvalidArgumentException;
use Psr\Http\Message\ResponseInterface;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RuntimeException;

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
     * OpenIdConfigurationProvider constructor.
     *
     * @param array $options
     * @param array $collaborators
     *
     * @throws ItkOpenIdConnectException
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
            throw new ItkOpenIdConnectException('OpenIDConnectMetadataUrl is invalid: ' . $url);
        }

        if (parse_url($url, PHP_URL_SCHEME) !== 'https') {
            throw new ItkOpenIdConnectException('OpenIDConnectMetadataUrl must use https: ' . $url);
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
            throw new ItkOpenIdConnectException('Required parameter "state" missing');
        }

        // Enforce use of required nonce parameter
        // @see https://docs.microsoft.com/en-us/azure/active-directory-b2c/openid-connect#send-authentication-requests
        if (empty($options['nonce'])) {
            throw new ItkOpenIdConnectException('Required parameter "nonce" missing');
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
     *   Raw id token as string
     *
     * @return object The JWT's payload as a PHP object
     *
     * @throws IdentityProviderException
     * @throws ItkOpenIdConnectException
     */
    public function validateIdToken(string $idToken, string $nonce): \stdClass
    {
        try {
            $keys = $this->getJwtVerificationKeys();
            $claims = JWT::decode($idToken, $keys, ['RS256']);
            if ($claims->aud !== $this->clientId) {
                throw new IdentityProviderException('ID token has incorrect audience', 0, $claims->aud);
            }
            if ($claims->iss !== $this->getConfiguration('issuer')) {
                throw new IdentityProviderException('ID token has incorrect issuer', 0, $claims->iss);
            }
            if ($claims->nonce !== $nonce) {
                throw new IdentityProviderException('ID token has incorrect nonce', 0, $claims->nonce);
            }

            return $claims;
        } catch (\UnexpectedValueException $e) {
            throw new IdentityProviderException("ID token validation failed", 0, $e->getMessage());
        }
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
     */
    public function getDefaultScopes()
    {
        return $this->scopes;
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
            throw new IdentityProviderException($error, 0, $data);
        }
    }

    /**
     * @inheritdoc
     */
    protected function createResourceOwner(array $response, AccessToken $token): GenericResourceOwner
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
     */
    private function getJwtVerificationKeys(): array
    {
        $cacheKey = self::CACHE_KEY . 'jwks';
        $keys = [];

        try {
            $item = $this->cacheItemPool->getItem($cacheKey);

            if ($item->isHit()) {
                $keys = $item->get();
            } else {
                $keysUri = $this->getConfiguration('jwks_uri');
                $jwks = $this->fetchJsonResource($keysUri);

                foreach ($jwks['keys'] as $key) {
                    $kid = $key['kid'];
                    if ($key['kty'] === 'RSA') {
                        $e = self::base64urlDecode($key['e']);
                        $n = self::base64urlDecode($key['n']);
                        $keys[$kid] = XMLSecurityKey::convertRSA($n, $e);
                    } else {
                        throw new ItkOpenIdConnectException('Unsupported key data for key id: ' . $kid);
                    }
                }

                $item->set($keys);
                $item->expiresAfter($this->cacheDuration);
            }
        } catch (InvalidArgumentException $e) {
            // @TODO 1
        }

        return $keys;
    }

    private static function base64urlDecode($input)
    {
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * Fetch remote json resource
     *
     * @return array
     *   Json decoded to array
     *
     * @throws ItkOpenIdConnectException
     */
    private function fetchJsonResource(string $resourceUrl): array
    {
        try {
            $response = $this->getHttpClient()->request('GET', $resourceUrl);

            if (200 !== $response->getStatusCode()) {
                throw new ItkOpenIdConnectException('Cannot access json resource: ' .  $resourceUrl);
            }

            $content = $response->getBody()->getContents();

            return json_decode($content, true, 512, JSON_THROW_ON_ERROR);
        } catch (GuzzleException $e) {
            // @TODO 1
        } catch (RuntimeException $e) {
            // @TODO 2
        } catch (JsonException $e) {
            // @TODO 3
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
     */
    private function getConfiguration(string $key): string
    {
        $cacheKey = self::CACHE_KEY . 'configuration';
        try {
            $item = $this->cacheItemPool->getItem($cacheKey);
            if ($item->isHit()) {
                $configuration = $item->get();
            } else {
                $configuration = $this->fetchJsonResource($this->openIDConnectMetadataUrl);
                $item->set($configuration);
                $item->expiresAfter($this->cacheDuration);
                $this->cacheItemPool->save($item);
            }

            if (isset($configuration[$key])) {
                $value = $configuration[$key];
            } else {
                throw new \InvalidArgumentException('Required config key not defined: ' . $key);
            }

            return $value;
        } catch (InvalidArgumentException $e) {
            // @TODO 1
        } catch (ItkOpenIdConnectException $e) {
            // @TODO 2
        }
    }
}
