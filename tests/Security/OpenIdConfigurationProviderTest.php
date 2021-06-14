<?php

namespace Tests\Security;

use Firebase\JWT\SignatureInvalidException;
use GuzzleHttp\ClientInterface;
use ItkDev\OpenIdConnect\Exception\ClaimsException;
use ItkDev\OpenIdConnect\Exception\ItkOpenIdConnectException;
use ItkDev\OpenIdConnect\Exception\ValidationException;
use ItkDev\OpenIdConnect\Security\OpenIdConfigurationProvider;
use Mockery\Adapter\Phpunit\MockeryTestCase;
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

    public function testGetBaseAccessTokenUrl(): void
    {
        $tokenUrl = $this->provider->getBaseAccessTokenUrl([]);
        $expected = 'https://azure_b2c_test.b2clogin.com/azure_b2c_test.onmicrosoft.com/oauth2/v2.0/token?p=test-policy';

        $this->assertSame($expected, $tokenUrl);
    }

    /**
     * @runInSeparateProcess
     */
    public function testValidateIdTokenSuccess(): void
    {
        $mockJWT = \Mockery::mock('overload:Firebase\JWT\JWT', MockJWT::class);
        $mockClaims = $this->getMockClaims();

        $mockJWT->shouldReceive('decode')->andReturn($mockClaims);

        $this->provider->validateIdToken('token', self::NONCE);
    }

    /**
     * @runInSeparateProcess
     */
    public function testValidateIdTokenFailure(): void
    {
        $mockJWT = \Mockery::mock('overload:Firebase\JWT\JWT', MockJWT::class);
        $mockJWT->shouldReceive('decode')->andThrow(SignatureInvalidException::class, 'Signature verification failed');

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('ID token validation failed');

        $this->provider->validateIdToken('token', self::NONCE);
    }

    /**
     * @runInSeparateProcess
     */
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

    /**
     * @runInSeparateProcess
     */
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

    /**
     * @runInSeparateProcess
     */
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
