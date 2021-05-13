<?php

namespace Security;

use GuzzleHttp\ClientInterface;
use ItkDev\OpenIdConnect\Security\OpenIdConfigurationProvider;
use League\OAuth2\Client\Token\AccessToken;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

/**
 * @internal
 *
 * @coversNothing
 */
class OpenIdConfigurationProviderTest extends TestCase
{
    /**
     * @var OpenIdConfigurationProvider
     */
    private $provider;

    public function setUp(): void
    {
        parent::setUp();

        $mockOPenIdConfiguration = file_get_contents(__DIR__ . '/../MockData/openIdConfiguration.json');

        $mockStream = $this->createMock(StreamInterface::class);
        $mockStream->method('getContents')->willReturn($mockOPenIdConfiguration);

        $mockResponse = $this->createMock(ResponseInterface::class);
        $mockResponse->method('getStatusCode')->willReturn(200);
        $mockResponse->method('getBody')->willReturn($mockStream);

        $mockHttpClient = $this->createMock(ClientInterface::class);
        $mockHttpClient->method('request')->willReturn($mockResponse);

        $cacheItemMock = $this->createMock(CacheItemInterface::class);
        $cacheItemMock->method('isHit')->willReturn(false);

        $cacheItemPoolMock = $this->createMock(CacheItemPoolInterface::class);
        $cacheItemPoolMock->method('getItem')->willReturn($cacheItemMock);

        $this->provider = new OpenIdConfigurationProvider([
            'openIDConnectMetadataUrl' => 'https://some.url/openid-configuration',
            'cacheItemPool' => $cacheItemPoolMock,
            'clientId' => 'test_client_id',
            'clientSecret' => 'test_client_secret',
            'redirectUri' => 'https://redirect.url',
            ], [
            'httpClient' => $mockHttpClient,
        ]);

        $d = 1;
    }

    public function testGetBaseAuthorizationUrl(): void
    {
        $authUrl = $this->provider->getBaseAuthorizationUrl();
        $expected = 'https://azure_b2c_test.b2clogin.com/azure_b2c_test.onmicrosoft.com/oauth2/v2.0/authorize?p=test-policy';

        $this->assertSame($expected, $authUrl);
    }

    public function testGetAuthorizationUrl(): void
    {
        $authUrl = $this->provider->getAuthorizationUrl();
        $query = [];
        parse_str(parse_url($authUrl, PHP_URL_QUERY), $query);

        $this->assertSame($query['scope'], 'openid');
        $this->assertSame($query['response_type'], 'id_token');
        $this->assertSame($query['response_mode'], 'query');
    }

    public function testGetBaseAccessTokenUrl(): void
    {
        $tokenUrl = $this->provider->getBaseAccessTokenUrl([]);
        $expected = 'https://azure_b2c_test.b2clogin.com/azure_b2c_test.onmicrosoft.com/oauth2/v2.0/token?p=test-policy';

        $this->assertSame($expected, $tokenUrl);
    }
}
