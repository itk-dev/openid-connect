<?php

namespace Tests\Security;

use Firebase\JWT\SignatureInvalidException;
use GuzzleHttp\ClientInterface;
use ItkDev\OpenIdConnect\Exception\ClaimsException;
use ItkDev\OpenIdConnect\Exception\NegativeCacheDurationException;
use ItkDev\OpenIdConnect\Exception\NegativeLeewayException;
use ItkDev\OpenIdConnect\Exception\ItkOpenIdConnectException;
use ItkDev\OpenIdConnect\Exception\ValidationException;
use ItkDev\OpenIdConnect\Security\OpenIdConfigurationProvider;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

class OpenIdConfigurationProviderTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    private const CLIENT_ID = 'test_client_id';
    private const CLIENT_SECRET = 'test_client_secret';
    private const REDIRECT_URI = 'https://redirect.url';
    private const NONCE = '12345678';

    /**
     * @var OpenIdConfigurationProvider|null
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
            'cacheDuration' => 3600,
            'leeway' => 30,
            ], [
            'httpClient' => $mockHttpClient,
        ]);
    }

    public function testConstructCacheItemPool(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectDeprecationMessage('Required options not defined: cacheItemPool');

        $provider = new OpenIdConfigurationProvider([], []);
    }

    public function testConstructOpenIDConnectMetadataUrl(): void
    {
        $mockCacheItemPool = $this->createMock(CacheItemPoolInterface::class);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectDeprecationMessage('Required options not defined: openIDConnectMetadataUrl');

        $provider = new OpenIdConfigurationProvider([
            'cacheItemPool' => $mockCacheItemPool,
        ], []);
    }

    public function testConstructCacheDuration(): void
    {
        $mockCacheItemPool = $this->createMock(CacheItemPoolInterface::class);

        $this->expectException(NegativeCacheDurationException::class);
        $this->expectExceptionMessage('Cache Duration has to be a positive integer');

        $provider = new OpenIdConfigurationProvider([
            'cacheItemPool' => $mockCacheItemPool,
            'openIDConnectMetadataUrl' => 'https://some.url/openid-configuration',
            'cacheDuration' => -10
        ], []);
    }

    public function testConstructLeeway(): void
    {
        $mockCacheItemPool = $this->createMock(CacheItemPoolInterface::class);

        $this->expectException(NegativeLeewayException::class);
        $this->expectExceptionMessage('Leeway has to be a positive integer');

        $provider = new OpenIdConfigurationProvider([
            'cacheItemPool' => $mockCacheItemPool,
            'openIDConnectMetadataUrl' => 'https://some.url/openid-configuration',
            'leeway' => -10
        ], []);
    }

    public function testGenerateState(): void
    {
        $state = $this->provider->generateState(32);
        $this->assertSame(32, strlen($state));
        $this->assertSame($state, $this->provider->getState());
    }

    public function testGenerateNonce(): void
    {
        $nonce = $this->provider->generateNonce(32);
        $this->assertSame(32, strlen($nonce));
    }

    public function testGetBaseAuthorizationUrl(): void
    {
        $authUrl = $this->provider->getBaseAuthorizationUrl();
        $expected = 'https://azure_b2c_test.b2clogin.com/azure_b2c_test.onmicrosoft.com/oauth2/v2.0/authorize?p=test-policy';

        $this->assertSame($expected, $authUrl);
    }

    public function testGetGuarded(): void
    {
        $guarded = $this->provider->getGuarded();
        $expected = ['cacheItemPool', 'cacheDuration', 'openIDConnectMetadataUrl', 'leeway'];

        $this->assertSame($expected, $guarded);
    }

    public function testGetDefaultScopes(): void
    {
        $scopes = $this->provider->getDefaultScopes();
        $expected = ['openid'];

        $this->assertSame($expected, $scopes);
    }

    public function testGetAuthorizationUrl(): void
    {
        $state = '12345678';
        $nonce = 'abcdefghij';

        $authUrl = $this->provider->getAuthorizationUrl(['state' => $state, 'nonce' => $nonce]);
        $query = [];
        parse_str(parse_url($authUrl, PHP_URL_QUERY), $query);

        $this->assertSame('openid', $query['scope']);
        $this->assertSame('id_token', $query['response_type']);
        $this->assertSame('query', $query['response_mode']);
        $this->assertSame($state, $query['state']);
        $this->assertSame($nonce, $query['nonce']);
    }

    public function testGetAuthorizationUrlStateException(): void
    {
        $this->expectException(ItkOpenIdConnectException::class);
        $this->expectExceptionMessage('Required parameter "state" missing');

        $authUrl = $this->provider->getAuthorizationUrl(['nonce' => 'abcd']);
    }

    public function testGetAuthorizationUrlNonceException(): void
    {
        $this->expectException(ItkOpenIdConnectException::class);
        $this->expectExceptionMessage('Required parameter "nonce" missing');

        $authUrl = $this->provider->getAuthorizationUrl(['state' => 'abcd']);
    }

    public function testGetEndSessionUrl(): void
    {
        // Defined in MockData/mockOpenIDConfiguration.json
        $expected = 'https://azure_b2c_test.b2clogin.com/azure_b2c_test.onmicrosoft.com/oauth2/v2.0/logout?p=test-policy';

        $endSessionUrl = $this->provider->getEndSessionUrl();
        $this->assertSame($expected, $endSessionUrl);

        $expectedUrl = $expected . '&post_logout_redirect_uri=https%3A%2F%2Flogout.test';
        $endSessionUrl = $this->provider->getEndSessionUrl('https://logout.test');
        $this->assertSame($expectedUrl, $endSessionUrl);

        $expectedState = $expected . '&state=test-state';
        $endSessionUrl = $this->provider->getEndSessionUrl(null, 'test-state');
        $this->assertSame($expectedState, $endSessionUrl);

        $expectedBoth = $expected . '&post_logout_redirect_uri=https%3A%2F%2Flogout.test' . '&state=test-state';
        $endSessionUrl = $this->provider->getEndSessionUrl('https://logout.test', 'test-state');
        $this->assertSame($expectedBoth, $endSessionUrl);
    }


    public function testGetBaseAccessTokenUrl(): void
    {
        $tokenUrl = $this->provider->getBaseAccessTokenUrl([]);
        $expected = 'https://azure_b2c_test.b2clogin.com/azure_b2c_test.onmicrosoft.com/oauth2/v2.0/token?p=test-policy';

        $this->assertSame($expected, $tokenUrl);
    }


    public function testValidateIdTokenSuccess(): void
    {
        $mockJWT = \Mockery::mock('overload:Firebase\JWT\JWT', MockJWT::class);
        $mockClaims = $this->getMockClaims();

        $mockJWT->shouldReceive('decode')->andReturn($mockClaims);

        $this->provider->validateIdToken('token', self::NONCE);
    }


    public function testValidateIdTokenFailure(): void
    {
        $mockJWT = \Mockery::mock('overload:Firebase\JWT\JWT', MockJWT::class);
        $mockJWT->shouldReceive('decode')->andThrow(SignatureInvalidException::class, 'Signature verification failed');

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('ID token validation failed');

        $this->provider->validateIdToken('token', self::NONCE);
    }


    public function testValidateIdTokenAudience(): void
    {
        $mockJWT = \Mockery::mock('overload:Firebase\JWT\JWT', MockJWT::class);
        $mockClaims = $this->getMockClaims();
        $mockClaims->aud = 'incorrect aud';

        $mockJWT->shouldReceive('decode')->andReturn($mockClaims);

        $this->expectException(ClaimsException::class);
        $this->expectExceptionMessage('ID token has incorrect audience');

        $this->provider->validateIdToken('token', self::NONCE);
    }


    public function testValidateIdTokenIssuer(): void
    {
        $mockJWT = \Mockery::mock('overload:Firebase\JWT\JWT', MockJWT::class);
        $mockClaims = $this->getMockClaims();
        $mockClaims->iss = 'incorrect iss';

        $mockJWT->shouldReceive('decode')->andReturn($mockClaims);

        $this->expectException(ClaimsException::class);
        $this->expectExceptionMessage('ID token has incorrect issuer');

        $this->provider->validateIdToken('token', self::NONCE);
    }


    public function testValidateIdTokenNonce(): void
    {
        $mockJWT = \Mockery::mock('overload:Firebase\JWT\JWT', MockJWT::class);
        $mockClaims = $this->getMockClaims();
        $mockClaims->nonce = 'incorrect nonce';

        $mockJWT->shouldReceive('decode')->andReturn($mockClaims);

        $this->expectException(ClaimsException::class);
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
