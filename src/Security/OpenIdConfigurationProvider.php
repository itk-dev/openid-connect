<?php

declare(strict_types=1);

namespace ItkDev\OpenIdConnect\Security;

use GuzzleHttp\Exception\GuzzleException;
use ItkDev\OpenIdConnect\Exception\ItkOpenIdConnectException;
use JsonException;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\GenericResourceOwner;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Cache\InvalidArgumentException;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

/**
 * Class OpenIdConfigurationProvider.
 *
 * @see https://github.com/cirrusidentity/simplesamlphp-module-authoauth2/blob/master/lib/Providers/OpenIDConnectProvider.php
 */
class OpenIdConfigurationProvider extends AbstractProvider
{
    private CONST CACHE_KEY = 'itk-openid-connect-configuration';

    /**
     * @var string
     */
    protected $openIDConnectMetadataUrl;

    /**
     * @var CacheItemPoolInterface
     */
    private $cacheItemPool;

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
        if (!array_key_exists('cacheItemPool', $options)) {
            throw new \InvalidArgumentException(
                'Required options not defined: cacheItemPool'
            );
        }
        $this->setCacheItemPool($options['cacheItemPool']);

        if (!array_key_exists('openIDConnectMetadataUrl', $options)) {
            throw new \InvalidArgumentException(
                'Required options not defined: openIDConnectMetadataUrl'
            );
        }
        $this->setOpenIDConnectMetadataUrl($options['openIDConnectMetadataUrl']);

        // The parent will attempt to set these again if we don't remove them.
//        unset($options['cacheItemPool']);
//        unset($options['openIDConnectMetadataUrl']);

        parent::__construct($options, $collaborators);
    }

    /**
     * {@inheritdoc}
     */
    public function getGuarded()
    {
        return ['cacheItemPool', 'openIDConnectMetadataUrl'];
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
     */
    public function getAuthorizationUrl(array $options = []): string
    {
        // Add default options scope, response_type and response_mode
        return parent::getAuthorizationUrl($options + [
            'scope' => 'openid',
            'response_type' => 'id_token',
            'response_mode' => 'query',
        ]);
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
    public function getAccessToken($grant, array $options = [])
    {
        return parent::getAccessToken($grant, $options); // TODO: Change the autogenerated stub
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
    protected function checkResponse(ResponseInterface $response, $data)
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
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new GenericResourceOwner($response, $this->responseResourceOwnerId);
    }

    /**
     * Refresh Cache.
     *
     * OpenIDConnectMetadata
     *
     * @throws ItkOpenIdConnectException
     */
    private function fetchOpenIDConnectMetadata(): array
    {
        try {
            $response = $this->getHttpClient()->request('GET', $this->openIDConnectMetadataUrl);

            if (200 !== $response->getStatusCode()) {
                throw new ItkOpenIdConnectException('Cannot access OpenID configuration resource.');
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
     * Get Configuration for key.
     */
    private function getConfiguration(string $key): string
    {
        try {
            $item = $this->cacheItemPool->getItem(self::CACHE_KEY);
            if ($item->isHit()) {
                $configuration = $item->get();
            } else {
                $configuration = $this->fetchOpenIDConnectMetadata();
            }

            if (isset($configuration[$key])) {
                return $configuration[$key];
            } else {
                throw new \InvalidArgumentException(
                    'Required config key not defined: '.$key
                );
            }
        } catch (InvalidArgumentException $e) {
            // @TODO 1
        } catch (ItkOpenIdConnectException $e) {
            // @TODO 2
        }
    }

    /**
     * Set the provider cache itm pool
     *
     * @param CacheItemPoolInterface $cacheItemPool
     */
    private function setCacheItemPool(CacheItemPoolInterface $cacheItemPool): void
    {
        $this->cacheItemPool = $cacheItemPool;
    }

    /**
     * Set the OpenID Connect Metadata Url
     *
     * @param string $url
     *
     * @throws ItkOpenIdConnectException
     */
    private function setOpenIDConnectMetadataUrl(string $url): void
    {
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            throw new ItkOpenIdConnectException('OpenIDConnectMetadataUrl is invalid: '.$url);
        }

        if (parse_url($url, PHP_URL_SCHEME) !== 'https') {
            throw new ItkOpenIdConnectException('OpenIDConnectMetadataUrl must use https: '.$url);
        }

        $this->openIDConnectMetadataUrl = $url;
    }
}
