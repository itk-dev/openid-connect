<?php

namespace Security;

use Firebase\JWT\SignatureInvalidException;
use GuzzleHttp\ClientInterface;
use ItkDev\OpenIdConnect\Security\OpenIdConfigurationProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Mockery\Adapter\Phpunit\MockeryTestCase;
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
class OpenIdConfigurationProviderTest extends MockeryTestCase
{
    private const CLIENT_ID = 'test_client_id';
    private const CLIENT_SECRET = 'test_client_secret';
    private const REDIRECT_URI = 'https://redirect.url';
    private const NONCE = '12345678';

    /**
     * @var OpenIdConfigurationProvider
     */
    private $provider;

    public function setUp(): void
    {
        parent::setUp();

        $openIDConnectMetadataUrl = 'https://some.url/openid-configuration';
        $jwks_uri = 'https://azure_b2c_test.b2clogin.com/azure_b2c_test.onmicrosoft.com/discovery/v2.0/keys?p=test-policy';

        $mockConfigResponse = $this->getMockHttpSuccessResponse('/../MockData/mockOpenIDConfiguration.json');
        $mockKeysResponse = $this->getMockHttpSuccessResponse('/../MockData/mockOpenIDValidationKeys.json');

        $requestMap = [
            ['GET', $openIDConnectMetadataUrl, [], $mockConfigResponse],
            ['GET', $jwks_uri, [], $mockKeysResponse],
        ];

        $mockHttpClient = $this->createMock(ClientInterface::class);
        $mockHttpClient->method('request')->will($this->returnValueMap($requestMap));

        $mockCacheItem = $this->createMock(CacheItemInterface::class);
        $mockCacheItem->method('isHit')->willReturn(false);

        $mockCacheItemPool = $this->createMock(CacheItemPoolInterface::class);
        $mockCacheItemPool->method('getItem')->willReturn($mockCacheItem);

        $this->provider = new OpenIdConfigurationProvider([
            'openIDConnectMetadataUrl' => $openIDConnectMetadataUrl,
            'cacheItemPool' => $mockCacheItemPool,
            'clientId' => self::CLIENT_ID,
            'clientSecret' => self::CLIENT_SECRET,
            'redirectUri' => self::REDIRECT_URI,
            ], [
            'httpClient' => $mockHttpClient,
        ]);
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

    public function testValidateIdTokenSuccess(): void
    {
        $mockJWT = \Mockery::mock('alias:Firebase\JWT\JWT');
        $mockClaims = $this->getMockClaims();

        $mockJWT->shouldReceive('decode')->andReturn($mockClaims);

        $this->provider->validateIdToken('token', self::NONCE);
    }

    public function testValidateIdTokenFailure(): void
    {
        $mockJWT = \Mockery::mock('alias:Firebase\JWT\JWT');
        $mockJWT->shouldReceive('decode')->andThrow(SignatureInvalidException::class, 'Signature verification failed');

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('ID token validation failed');

        $this->provider->validateIdToken('token', self::NONCE);
    }

    public function testValidateIdTokenAudience(): void
    {
        $mockJWT = \Mockery::mock('alias:Firebase\JWT\JWT');
        $mockClaims = $this->getMockClaims();
        $mockClaims->aud = 'incorrect aud';

        $mockJWT->shouldReceive('decode')->andReturn($mockClaims);

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('ID token has incorrect audience');

        $this->provider->validateIdToken('token', self::NONCE);
    }

    public function testValidateIdTokenIssuer(): void
    {
        $mockJWT = \Mockery::mock('alias:Firebase\JWT\JWT');
        $mockClaims = $this->getMockClaims();
        $mockClaims->iss = 'incorrect iss';

        $mockJWT->shouldReceive('decode')->andReturn($mockClaims);

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('ID token has incorrect issuer');

        $this->provider->validateIdToken('token', self::NONCE);
    }

    public function testValidateIdTokenNonce(): void
    {
        $mockJWT = \Mockery::mock('alias:Firebase\JWT\JWT');
        $mockClaims = $this->getMockClaims();
        $mockClaims->nonce = 'incorrect nonce';

        $mockJWT->shouldReceive('decode')->andReturn($mockClaims);

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('ID token has incorrect nonce');

        $this->provider->validateIdToken('token', self::NONCE);
    }

    /**
     * Get a mock success response with mock date
     *
     * @param string $mockResponseDataPath
     *   Path to the file containing the mock response data
     *
     * @return ResponseInterface
     *   A success ("200") response with mock body data
     */
    private function getMockHttpSuccessResponse(string $mockResponseDataPath): ResponseInterface
    {
        $mockResponseData = file_get_contents(__DIR__ . $mockResponseDataPath);

        $mockStream = $this->createMock(StreamInterface::class);
        $mockStream->method('getContents')->willReturn($mockResponseData);

        $mockResponse = $this->createMock(ResponseInterface::class);
        $mockResponse->method('getStatusCode')->willReturn(200);
        $mockResponse->method('getBody')->willReturn($mockStream);

        return $mockResponse;
    }

    /**
     * Get a stdClass object of mock claims
     *
     * @return \stdClass
     */
    private function getMockClaims(): \stdClass
    {
        $mockClaims = new \stdClass();
        $mockClaims->aud = self::CLIENT_ID;
        // Defined in ../MockData/mockOpenIDConfiguration.json
        // "issuer": "https://azure_b2c_test.b2clogin.com/11111111-1111-1111-1111-111111111111/v2.0/",
        $mockClaims->iss = 'https://azure_b2c_test.b2clogin.com/11111111-1111-1111-1111-111111111111/v2.0/';
        $mockClaims->nonce = self::NONCE;

        return $mockClaims;
    }
}
