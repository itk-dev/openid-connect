<?php

namespace Tests\Security;

use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use GuzzleHttp\ClientInterface;
use Hamcrest\Matchers as m;
use ItkDev\OpenIdConnect\Exception\BadUrlException;
use ItkDev\OpenIdConnect\Exception\CacheException;
use ItkDev\OpenIdConnect\Exception\ClaimsException;
use ItkDev\OpenIdConnect\Exception\CodeException;
use ItkDev\OpenIdConnect\Exception\HttpException;
use ItkDev\OpenIdConnect\Exception\IllegalSchemeException;
use ItkDev\OpenIdConnect\Exception\KeyException;
use ItkDev\OpenIdConnect\Exception\MissingParameterException;
use ItkDev\OpenIdConnect\Exception\NegativeCacheDurationException;
use ItkDev\OpenIdConnect\Exception\NegativeLeewayException;
use ItkDev\OpenIdConnect\Exception\ValidationException;
use ItkDev\OpenIdConnect\Security\OpenIdConfigurationProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

class OpenIdConfigurationProviderTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    private const CLIENT_ID = 'test_client_id';
    private const CLIENT_SECRET = 'test_client_secret';
    private const REDIRECT_URI = 'https://redirect.url';
    private const NONCE = '12345678';

    private OpenIdConfigurationProvider $provider;

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

        $mockHttpClient = $this->createStub(ClientInterface::class);
        $mockHttpClient->method('request')->willReturnMap($requestMap);

        $mockCacheItem = $this->createStub(CacheItemInterface::class);
        $mockCacheItem->method('isHit')->willReturn(false);

        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);
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
        $this->expectExceptionMessage('Required options not defined: cacheItemPool');

        $provider = new OpenIdConfigurationProvider([], []);
    }

    public function testConstructOpenIDConnectMetadataUrl(): void
    {
        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Required options not defined: openIDConnectMetadataUrl');

        $provider = new OpenIdConfigurationProvider([
            'cacheItemPool' => $mockCacheItemPool,
        ], []);
    }

    public function testConstructCacheDuration(): void
    {
        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);

        $this->expectException(NegativeCacheDurationException::class);
        $this->expectExceptionMessage('Cache Duration has to be a positive integer');

        $provider = new OpenIdConfigurationProvider([
            'cacheItemPool' => $mockCacheItemPool,
            'openIDConnectMetadataUrl' => 'https://some.url/openid-configuration',
            'cacheDuration' => -10,
        ], []);
    }

    public function testConstructLeeway(): void
    {
        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);

        $this->expectException(NegativeLeewayException::class);
        $this->expectExceptionMessage('Leeway has to be a positive integer');

        $provider = new OpenIdConfigurationProvider([
            'cacheItemPool' => $mockCacheItemPool,
            'openIDConnectMetadataUrl' => 'https://some.url/openid-configuration',
            'leeway' => -10,
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
        $expected = ['cacheItemPool', 'cacheDuration', 'openIDConnectMetadataUrl', 'leeway', 'allowHttp'];

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
        $queryString = parse_url($authUrl, PHP_URL_QUERY);
        $this->assertIsString($queryString, 'Generated authorization URL must have a query string');
        parse_str($queryString, $query);

        $this->assertSame('openid', $query['scope']);
        $this->assertSame('id_token', $query['response_type']);
        $this->assertSame('query', $query['response_mode']);
        $this->assertSame($state, $query['state']);
        $this->assertSame($nonce, $query['nonce']);
    }

    public function testGetAuthorizationUrlStateException(): void
    {
        $this->expectException(MissingParameterException::class);
        $this->expectExceptionMessage('Required parameter "state" missing');

        $authUrl = $this->provider->getAuthorizationUrl(['nonce' => 'abcd']);
    }

    public function testGetAuthorizationUrlNonceException(): void
    {
        $this->expectException(MissingParameterException::class);
        $this->expectExceptionMessage('Required parameter "nonce" missing');

        $authUrl = $this->provider->getAuthorizationUrl(['state' => 'abcd']);
    }

    public function testGetEndSessionUrl(): void
    {
        // Defined in MockData/mockOpenIDConfiguration.json
        $expected = 'https://azure_b2c_test.b2clogin.com/azure_b2c_test.onmicrosoft.com/oauth2/v2.0/logout?p=test-policy';

        $endSessionUrl = $this->provider->getEndSessionUrl();
        $this->assertSame($expected, $endSessionUrl);

        $expectedUrl = $expected.'&post_logout_redirect_uri=https%3A%2F%2Flogout.test';
        $endSessionUrl = $this->provider->getEndSessionUrl('https://logout.test');
        $this->assertSame($expectedUrl, $endSessionUrl);

        $expectedState = $expected.'&state=test-state';
        $endSessionUrl = $this->provider->getEndSessionUrl(null, 'test-state');
        $this->assertSame($expectedState, $endSessionUrl);

        $expectedBoth = $expected.'&post_logout_redirect_uri=https%3A%2F%2Flogout.test&state=test-state';
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

        // Assert that 'decode' is called as decode(<string>, [<string>, <Firebase\JWT\Key>])
        // @see https://github.com/firebase/php-jwt/issues/432
        $mockJWT->shouldReceive('decode')
            ->with(
                \Mockery::type('string'),
                m::hasKeyValuePair(
                    '111111111111111111111111111111111111111111',
                    m::anInstanceOf(Key::class)
                )
            )->andReturn($mockClaims);

        /** @var object{nonce: string, aud: string|list<string>} $claims */
        $claims = $this->provider->validateIdToken('token', self::NONCE);

        $this->assertEquals(self::NONCE, $claims->nonce);
        $this->assertEquals(self::CLIENT_ID, $claims->aud);
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

    public function testConstructBadUrl(): void
    {
        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);

        $this->expectException(BadUrlException::class);
        $this->expectExceptionMessage('OpenIDConnectMetadataUrl is invalid');

        new OpenIdConfigurationProvider([
            'cacheItemPool' => $mockCacheItemPool,
            'openIDConnectMetadataUrl' => 'not-a-valid-url',
        ], []);
    }

    public function testConstructHttpUrlNotAllowed(): void
    {
        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);

        $this->expectException(IllegalSchemeException::class);
        $this->expectExceptionMessage('OpenIDConnectMetadataUrl must use https');

        new OpenIdConfigurationProvider([
            'cacheItemPool' => $mockCacheItemPool,
            'openIDConnectMetadataUrl' => 'http://some.url/openid-configuration',
        ], []);
    }

    public function testConstructHttpUrlAllowed(): void
    {
        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);
        $mockCacheItem = $this->createStub(CacheItemInterface::class);
        $mockCacheItem->method('isHit')->willReturn(false);
        $mockCacheItemPool->method('getItem')->willReturn($mockCacheItem);

        $mockHttpClient = $this->createStub(ClientInterface::class);

        $provider = new OpenIdConfigurationProvider([
            'cacheItemPool' => $mockCacheItemPool,
            'openIDConnectMetadataUrl' => 'http://some.url/openid-configuration',
            'allowHttp' => true,
            'clientId' => self::CLIENT_ID,
            'clientSecret' => self::CLIENT_SECRET,
            'redirectUri' => self::REDIRECT_URI,
        ], [
            'httpClient' => $mockHttpClient,
        ]);

        $this->assertInstanceOf(OpenIdConfigurationProvider::class, $provider);
    }

    public function testGetEndSessionUrlWithIdToken(): void
    {
        $expected = 'https://azure_b2c_test.b2clogin.com/azure_b2c_test.onmicrosoft.com/oauth2/v2.0/logout?p=test-policy';

        $expectedWithToken = $expected.'&id_token_hint=my-id-token';
        $endSessionUrl = $this->provider->getEndSessionUrl(null, null, 'my-id-token');
        $this->assertSame($expectedWithToken, $endSessionUrl);

        $expectedAll = $expected.'&post_logout_redirect_uri=https%3A%2F%2Flogout.test&state=test-state&id_token_hint=my-id-token';
        $endSessionUrl = $this->provider->getEndSessionUrl('https://logout.test', 'test-state', 'my-id-token');
        $this->assertSame($expectedAll, $endSessionUrl);
    }

    public function testGetResourceOwnerDetailsUrl(): void
    {
        $token = $this->createStub(AccessToken::class);
        $url = $this->provider->getResourceOwnerDetailsUrl($token);
        $expected = 'https://azure_b2c_test.b2clogin.com/azure_b2c_test.onmicrosoft.com/openid/userinfo?p=test-policy';

        $this->assertSame($expected, $url);
    }

    public function testCheckResponseSuccess(): void
    {
        $this->expectNotToPerformAssertions();

        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);

        $method = new \ReflectionMethod(OpenIdConfigurationProvider::class, 'checkResponse');

        // Should not throw
        $method->invoke($this->provider, $response, ['data' => 'value']);
    }

    public function testCheckResponseWithErrorString(): void
    {
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);

        $method = new \ReflectionMethod(OpenIdConfigurationProvider::class, 'checkResponse');

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('something went wrong');

        $method->invoke($this->provider, $response, ['error' => 'something went wrong']);
    }

    public function testCheckResponseWithNonStringError(): void
    {
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);

        $method = new \ReflectionMethod(OpenIdConfigurationProvider::class, 'checkResponse');

        $this->expectException(IdentityProviderException::class);

        $method->invoke($this->provider, $response, ['error' => ['code' => 123]]);
    }

    public function testCheckResponseWithErrorStatusCode(): void
    {
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(400);

        $method = new \ReflectionMethod(OpenIdConfigurationProvider::class, 'checkResponse');

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage('400');

        $method->invoke($this->provider, $response, []);
    }

    public function testCreateResourceOwner(): void
    {
        $token = $this->createStub(AccessToken::class);

        $method = new \ReflectionMethod(OpenIdConfigurationProvider::class, 'createResourceOwner');

        $owner = $method->invoke($this->provider, ['id' => '123', 'name' => 'Test'], $token);
        $this->assertSame('123', $owner->getId());
    }

    public function testValidateIdTokenArrayAudience(): void
    {
        $mockJWT = \Mockery::mock('overload:Firebase\JWT\JWT', MockJWT::class);
        $mockClaims = $this->getMockClaims();
        $mockClaims->aud = [self::CLIENT_ID, 'other_client'];

        $mockJWT->shouldReceive('decode')->andReturn($mockClaims);

        /** @var object{nonce: string, aud: string|list<string>} $claims */
        $claims = $this->provider->validateIdToken('token', self::NONCE);

        $this->assertEquals(self::NONCE, $claims->nonce);
        $this->assertContains(self::CLIENT_ID, (array) $claims->aud);
    }

    public function testValidateIdTokenArrayAudienceInvalid(): void
    {
        $mockJWT = \Mockery::mock('overload:Firebase\JWT\JWT', MockJWT::class);
        $mockClaims = $this->getMockClaims();
        $mockClaims->aud = ['wrong_client_1', 'wrong_client_2'];

        $mockJWT->shouldReceive('decode')->andReturn($mockClaims);

        $this->expectException(ClaimsException::class);
        $this->expectExceptionMessage('ID token has incorrect audience');

        $this->provider->validateIdToken('token', self::NONCE);
    }

    public function testGetIdTokenSuccess(): void
    {
        $tokenEndpoint = 'https://azure_b2c_test.b2clogin.com/azure_b2c_test.onmicrosoft.com/oauth2/v2.0/token?p=test-policy';
        $openIDConnectMetadataUrl = 'https://some.url/openid-configuration';
        $jwks_uri = 'https://azure_b2c_test.b2clogin.com/azure_b2c_test.onmicrosoft.com/discovery/v2.0/keys?p=test-policy';

        $mockConfigResponse = $this->getMockHttpSuccessResponse('/../MockData/mockOpenIDConfiguration.json');
        $mockKeysResponse = $this->getMockHttpSuccessResponse('/../MockData/mockOpenIDValidationKeys.json');

        $tokenResponseBody = json_encode(['id_token' => 'the-id-token']);
        $mockTokenStream = $this->createStub(StreamInterface::class);
        $mockTokenStream->method('getContents')->willReturn($tokenResponseBody);
        $mockTokenStream->method('__toString')->willReturn($tokenResponseBody);

        $mockTokenResponse = $this->createStub(ResponseInterface::class);
        $mockTokenResponse->method('getStatusCode')->willReturn(200);
        $mockTokenResponse->method('getBody')->willReturn($mockTokenStream);

        $mockHttpClient = $this->createStub(ClientInterface::class);
        $mockHttpClient->method('request')->willReturnMap([
            ['GET', $openIDConnectMetadataUrl, [], $mockConfigResponse],
            ['GET', $jwks_uri, [], $mockKeysResponse],
            ['POST', $tokenEndpoint, ['form_params' => [
                'client_id' => self::CLIENT_ID,
                'client_secret' => self::CLIENT_SECRET,
                'redirect_uri' => self::REDIRECT_URI,
                'grant_type' => 'authorization_code',
                'code' => 'test-code',
            ]], $mockTokenResponse],
        ]);

        $mockCacheItem = $this->createStub(CacheItemInterface::class);
        $mockCacheItem->method('isHit')->willReturn(false);

        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);
        $mockCacheItemPool->method('getItem')->willReturn($mockCacheItem);

        $provider = new OpenIdConfigurationProvider([
            'openIDConnectMetadataUrl' => $openIDConnectMetadataUrl,
            'cacheItemPool' => $mockCacheItemPool,
            'clientId' => self::CLIENT_ID,
            'clientSecret' => self::CLIENT_SECRET,
            'redirectUri' => self::REDIRECT_URI,
        ], [
            'httpClient' => $mockHttpClient,
        ]);

        $idToken = $provider->getIdToken('test-code');
        $this->assertSame('the-id-token', $idToken);
    }

    public function testGetIdTokenFailure(): void
    {
        $openIDConnectMetadataUrl = 'https://some.url/openid-configuration';

        $mockHttpClient = $this->createStub(ClientInterface::class);
        // PSR-18 transport stub — Guzzle's real exceptions need a RequestInterface
        // we don't have here, and any ClientExceptionInterface satisfies getIdToken's catch.
        $mockHttpClient->method('request')->willThrowException(
            new class('Connection failed') extends \RuntimeException implements ClientExceptionInterface {}
        );

        $mockCacheItem = $this->createStub(CacheItemInterface::class);
        $mockCacheItem->method('isHit')->willReturn(false);

        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);
        $mockCacheItemPool->method('getItem')->willReturn($mockCacheItem);

        $provider = new OpenIdConfigurationProvider([
            'openIDConnectMetadataUrl' => $openIDConnectMetadataUrl,
            'cacheItemPool' => $mockCacheItemPool,
            'clientId' => self::CLIENT_ID,
            'clientSecret' => self::CLIENT_SECRET,
            'redirectUri' => self::REDIRECT_URI,
        ], [
            'httpClient' => $mockHttpClient,
        ]);

        $this->expectException(CodeException::class);
        $this->expectExceptionMessage('Get ID token failed');

        $provider->getIdToken('test-code');
    }

    public function testGetConfigurationCacheHit(): void
    {
        $configuration = $this->loadMockFixture('mockOpenIDConfiguration.json');

        $mockCacheItem = $this->createStub(CacheItemInterface::class);
        $mockCacheItem->method('isHit')->willReturn(true);
        $mockCacheItem->method('get')->willReturn($configuration);

        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);
        $mockCacheItemPool->method('getItem')->willReturn($mockCacheItem);

        $mockHttpClient = $this->createStub(ClientInterface::class);

        $provider = new OpenIdConfigurationProvider([
            'openIDConnectMetadataUrl' => 'https://some.url/openid-configuration',
            'cacheItemPool' => $mockCacheItemPool,
            'clientId' => self::CLIENT_ID,
            'clientSecret' => self::CLIENT_SECRET,
            'redirectUri' => self::REDIRECT_URI,
        ], [
            'httpClient' => $mockHttpClient,
        ]);

        $authUrl = $provider->getBaseAuthorizationUrl();
        $this->assertSame($configuration['authorization_endpoint'], $authUrl);
    }

    public function testGetConfigurationMissingKey(): void
    {
        $this->expectException(\ItkDev\OpenIdConnect\Exception\MetadataException::class);
        $this->expectExceptionMessage('OIDC discovery document missing required key: nonexistent_key');

        $method = new \ReflectionMethod(OpenIdConfigurationProvider::class, 'getConfiguration');
        $method->invoke($this->provider, 'nonexistent_key');
    }

    public function testGetConfigurationNonStringValue(): void
    {
        $mockCacheItem = $this->createStub(CacheItemInterface::class);
        $mockCacheItem->method('isHit')->willReturn(true);
        $mockCacheItem->method('get')->willReturn(['authorization_endpoint' => 42]);

        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);
        $mockCacheItemPool->method('getItem')->willReturn($mockCacheItem);

        $provider = new OpenIdConfigurationProvider([
            'openIDConnectMetadataUrl' => 'https://some.url/openid-configuration',
            'cacheItemPool' => $mockCacheItemPool,
            'clientId' => self::CLIENT_ID,
            'clientSecret' => self::CLIENT_SECRET,
            'redirectUri' => self::REDIRECT_URI,
        ], [
            'httpClient' => $this->createStub(ClientInterface::class),
        ]);

        $this->expectException(\ItkDev\OpenIdConnect\Exception\MetadataException::class);
        $this->expectExceptionMessage('OIDC discovery document value for "authorization_endpoint" is not a string (got int)');

        $method = new \ReflectionMethod(OpenIdConfigurationProvider::class, 'getConfiguration');
        $method->invoke($provider, 'authorization_endpoint');
    }

    public function testFetchJsonResourceNon200(): void
    {
        $openIDConnectMetadataUrl = 'https://some.url/openid-configuration';

        $mockStream = $this->createStub(StreamInterface::class);
        $mockStream->method('getContents')->willReturn('');

        $mockResponse = $this->createStub(ResponseInterface::class);
        $mockResponse->method('getStatusCode')->willReturn(500);
        $mockResponse->method('getBody')->willReturn($mockStream);

        $mockHttpClient = $this->createStub(ClientInterface::class);
        $mockHttpClient->method('request')->willReturn($mockResponse);

        $mockCacheItem = $this->createStub(CacheItemInterface::class);
        $mockCacheItem->method('isHit')->willReturn(false);

        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);
        $mockCacheItemPool->method('getItem')->willReturn($mockCacheItem);

        $provider = new OpenIdConfigurationProvider([
            'openIDConnectMetadataUrl' => $openIDConnectMetadataUrl,
            'cacheItemPool' => $mockCacheItemPool,
            'clientId' => self::CLIENT_ID,
            'clientSecret' => self::CLIENT_SECRET,
            'redirectUri' => self::REDIRECT_URI,
        ], [
            'httpClient' => $mockHttpClient,
        ]);

        $this->expectException(HttpException::class);
        $this->expectExceptionMessage('Cannot access json resource');

        $provider->getBaseAuthorizationUrl();
    }

    public function testFetchJsonResourceClientException(): void
    {
        $openIDConnectMetadataUrl = 'https://some.url/openid-configuration';

        $mockHttpClient = $this->createStub(ClientInterface::class);
        $exception = new class('Connection refused') extends \RuntimeException implements ClientExceptionInterface {
        };
        $mockHttpClient->method('request')->willThrowException($exception);

        $mockCacheItem = $this->createStub(CacheItemInterface::class);
        $mockCacheItem->method('isHit')->willReturn(false);

        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);
        $mockCacheItemPool->method('getItem')->willReturn($mockCacheItem);

        $provider = new OpenIdConfigurationProvider([
            'openIDConnectMetadataUrl' => $openIDConnectMetadataUrl,
            'cacheItemPool' => $mockCacheItemPool,
            'clientId' => self::CLIENT_ID,
            'clientSecret' => self::CLIENT_SECRET,
            'redirectUri' => self::REDIRECT_URI,
        ], [
            'httpClient' => $mockHttpClient,
        ]);

        $this->expectException(HttpException::class);
        $this->expectExceptionMessage('Connection refused');

        $provider->getBaseAuthorizationUrl();
    }

    public function testFetchJsonResourceInvalidJson(): void
    {
        $openIDConnectMetadataUrl = 'https://some.url/openid-configuration';

        $mockStream = $this->createStub(StreamInterface::class);
        $mockStream->method('getContents')->willReturn('not valid json{{{');

        $mockResponse = $this->createStub(ResponseInterface::class);
        $mockResponse->method('getStatusCode')->willReturn(200);
        $mockResponse->method('getBody')->willReturn($mockStream);

        $mockHttpClient = $this->createStub(ClientInterface::class);
        $mockHttpClient->method('request')->willReturn($mockResponse);

        $mockCacheItem = $this->createStub(CacheItemInterface::class);
        $mockCacheItem->method('isHit')->willReturn(false);

        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);
        $mockCacheItemPool->method('getItem')->willReturn($mockCacheItem);

        $provider = new OpenIdConfigurationProvider([
            'openIDConnectMetadataUrl' => $openIDConnectMetadataUrl,
            'cacheItemPool' => $mockCacheItemPool,
            'clientId' => self::CLIENT_ID,
            'clientSecret' => self::CLIENT_SECRET,
            'redirectUri' => self::REDIRECT_URI,
        ], [
            'httpClient' => $mockHttpClient,
        ]);

        $this->expectException(\ItkDev\OpenIdConnect\Exception\JsonException::class);

        $provider->getBaseAuthorizationUrl();
    }

    public function testGetJwtVerificationKeysRejectsNonStringKid(): void
    {
        $openIDConnectMetadataUrl = 'https://some.url/openid-configuration';
        $jwks_uri = 'https://azure_b2c_test.b2clogin.com/azure_b2c_test.onmicrosoft.com/discovery/v2.0/keys?p=test-policy';

        $mockConfigResponse = $this->getMockHttpSuccessResponse('/../MockData/mockOpenIDConfiguration.json');

        // JWK with an int `kid` — violates RFC 7517 §4.5 (kid must be a string).
        $badJwks = json_encode(['keys' => [['kid' => 42, 'kty' => 'RSA', 'e' => 'AQAB', 'n' => 'abc']]]);
        $mockKeysStream = $this->createStub(StreamInterface::class);
        $mockKeysStream->method('getContents')->willReturn($badJwks);

        $mockKeysResponse = $this->createStub(ResponseInterface::class);
        $mockKeysResponse->method('getStatusCode')->willReturn(200);
        $mockKeysResponse->method('getBody')->willReturn($mockKeysStream);

        $mockHttpClient = $this->createStub(ClientInterface::class);
        $mockHttpClient->method('request')->willReturnMap([
            ['GET', $openIDConnectMetadataUrl, [], $mockConfigResponse],
            ['GET', $jwks_uri, [], $mockKeysResponse],
        ]);

        $mockCacheItem = $this->createStub(CacheItemInterface::class);
        $mockCacheItem->method('isHit')->willReturn(false);

        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);
        $mockCacheItemPool->method('getItem')->willReturn($mockCacheItem);

        $provider = new OpenIdConfigurationProvider([
            'openIDConnectMetadataUrl' => $openIDConnectMetadataUrl,
            'cacheItemPool' => $mockCacheItemPool,
            'clientId' => self::CLIENT_ID,
            'clientSecret' => self::CLIENT_SECRET,
            'redirectUri' => self::REDIRECT_URI,
        ], [
            'httpClient' => $mockHttpClient,
        ]);

        $mockJWT = \Mockery::mock('overload:Firebase\JWT\JWT', MockJWT::class);

        $this->expectException(KeyException::class);
        $this->expectExceptionMessage('JWK entry missing string "kid" (RFC 7517 §4.5)');

        $provider->validateIdToken('token', self::NONCE);
    }

    public function testGetJwtVerificationKeysUnsupportedKeyType(): void
    {
        $openIDConnectMetadataUrl = 'https://some.url/openid-configuration';
        $jwks_uri = 'https://azure_b2c_test.b2clogin.com/azure_b2c_test.onmicrosoft.com/discovery/v2.0/keys?p=test-policy';

        $mockConfigResponse = $this->getMockHttpSuccessResponse('/../MockData/mockOpenIDConfiguration.json');

        $ecKeyData = json_encode(['keys' => [['kid' => 'ec-key-1', 'kty' => 'EC', 'x' => 'abc', 'y' => 'def']]]);
        $mockKeysStream = $this->createStub(StreamInterface::class);
        $mockKeysStream->method('getContents')->willReturn($ecKeyData);

        $mockKeysResponse = $this->createStub(ResponseInterface::class);
        $mockKeysResponse->method('getStatusCode')->willReturn(200);
        $mockKeysResponse->method('getBody')->willReturn($mockKeysStream);

        $mockHttpClient = $this->createStub(ClientInterface::class);
        $mockHttpClient->method('request')->willReturnMap([
            ['GET', $openIDConnectMetadataUrl, [], $mockConfigResponse],
            ['GET', $jwks_uri, [], $mockKeysResponse],
        ]);

        $mockCacheItem = $this->createStub(CacheItemInterface::class);
        $mockCacheItem->method('isHit')->willReturn(false);

        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);
        $mockCacheItemPool->method('getItem')->willReturn($mockCacheItem);

        $provider = new OpenIdConfigurationProvider([
            'openIDConnectMetadataUrl' => $openIDConnectMetadataUrl,
            'cacheItemPool' => $mockCacheItemPool,
            'clientId' => self::CLIENT_ID,
            'clientSecret' => self::CLIENT_SECRET,
            'redirectUri' => self::REDIRECT_URI,
        ], [
            'httpClient' => $mockHttpClient,
        ]);

        $mockJWT = \Mockery::mock('overload:Firebase\JWT\JWT', MockJWT::class);

        $this->expectException(KeyException::class);
        $this->expectExceptionMessage('Unsupported key data for key id: ec-key-1');

        $provider->validateIdToken('token', self::NONCE);
    }

    public function testGetJwtVerificationKeysCacheHit(): void
    {
        $openIDConnectMetadataUrl = 'https://some.url/openid-configuration';

        $configuration = $this->loadMockFixture('mockOpenIDConfiguration.json');

        $cachedKeys = ['key1' => new Key('public-key-data', 'RS256')];

        $configCacheItem = $this->createStub(CacheItemInterface::class);
        $configCacheItem->method('isHit')->willReturn(true);
        $configCacheItem->method('get')->willReturn($configuration);

        $jwksCacheItem = $this->createStub(CacheItemInterface::class);
        $jwksCacheItem->method('isHit')->willReturn(true);
        $jwksCacheItem->method('get')->willReturn($cachedKeys);

        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);
        $mockCacheItemPool->method('getItem')->willReturnCallback(function (string $key) use ($configCacheItem, $jwksCacheItem) {
            if (str_contains($key, 'jwks')) {
                return $jwksCacheItem;
            }

            return $configCacheItem;
        });

        $mockHttpClient = $this->createStub(ClientInterface::class);

        $provider = new OpenIdConfigurationProvider([
            'openIDConnectMetadataUrl' => $openIDConnectMetadataUrl,
            'cacheItemPool' => $mockCacheItemPool,
            'clientId' => self::CLIENT_ID,
            'clientSecret' => self::CLIENT_SECRET,
            'redirectUri' => self::REDIRECT_URI,
        ], [
            'httpClient' => $mockHttpClient,
        ]);

        $mockJWT = \Mockery::mock('overload:Firebase\JWT\JWT', MockJWT::class);
        $mockClaims = $this->getMockClaims();
        $mockJWT->shouldReceive('decode')->andReturn($mockClaims);

        /** @var object{nonce: string} $claims */
        $claims = $provider->validateIdToken('token', self::NONCE);
        $this->assertEquals(self::NONCE, $claims->nonce);
    }

    public function testGetConfigurationCacheInvalidArgument(): void
    {
        $openIDConnectMetadataUrl = 'https://some.url/openid-configuration';

        $exception = new class('Invalid cache key') extends \InvalidArgumentException implements \Psr\Cache\InvalidArgumentException {
        };
        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);
        $mockCacheItemPool->method('getItem')->willThrowException($exception);

        $mockHttpClient = $this->createStub(ClientInterface::class);

        $provider = new OpenIdConfigurationProvider([
            'openIDConnectMetadataUrl' => $openIDConnectMetadataUrl,
            'cacheItemPool' => $mockCacheItemPool,
            'clientId' => self::CLIENT_ID,
            'clientSecret' => self::CLIENT_SECRET,
            'redirectUri' => self::REDIRECT_URI,
        ], [
            'httpClient' => $mockHttpClient,
        ]);

        $this->expectException(CacheException::class);
        $this->expectExceptionMessage('Invalid cache key');

        $provider->getBaseAuthorizationUrl();
    }

    public function testGetJwtVerificationKeysCacheInvalidArgument(): void
    {
        $openIDConnectMetadataUrl = 'https://some.url/openid-configuration';
        $configuration = $this->loadMockFixture('mockOpenIDConfiguration.json');

        $configCacheItem = $this->createStub(CacheItemInterface::class);
        $configCacheItem->method('isHit')->willReturn(true);
        $configCacheItem->method('get')->willReturn($configuration);

        $exception = new class('Invalid jwks cache key') extends \InvalidArgumentException implements \Psr\Cache\InvalidArgumentException {
        };

        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);
        $mockCacheItemPool->method('getItem')->willReturnCallback(function (string $key) use ($configCacheItem, $exception) {
            if (str_contains($key, 'jwks')) {
                throw $exception;
            }

            return $configCacheItem;
        });

        $mockHttpClient = $this->createStub(ClientInterface::class);

        $provider = new OpenIdConfigurationProvider([
            'openIDConnectMetadataUrl' => $openIDConnectMetadataUrl,
            'cacheItemPool' => $mockCacheItemPool,
            'clientId' => self::CLIENT_ID,
            'clientSecret' => self::CLIENT_SECRET,
            'redirectUri' => self::REDIRECT_URI,
        ], [
            'httpClient' => $mockHttpClient,
        ]);

        $this->expectException(CacheException::class);
        $this->expectExceptionMessage('Invalid jwks cache key');

        $provider->validateIdToken('token', self::NONCE);
    }

    public function testBase64urlDecodeFailure(): void
    {
        $openIDConnectMetadataUrl = 'https://some.url/openid-configuration';
        $jwks_uri = 'https://azure_b2c_test.b2clogin.com/azure_b2c_test.onmicrosoft.com/discovery/v2.0/keys?p=test-policy';

        $mockConfigResponse = $this->getMockHttpSuccessResponse('/../MockData/mockOpenIDConfiguration.json');

        // Use invalid base64 characters that will cause base64_decode to return false
        $invalidKeyData = json_encode(['keys' => [['kid' => 'bad-key', 'kty' => 'RSA', 'e' => '!!!', 'n' => 'valid']]]);
        $mockKeysStream = $this->createStub(StreamInterface::class);
        $mockKeysStream->method('getContents')->willReturn($invalidKeyData);

        $mockKeysResponse = $this->createStub(ResponseInterface::class);
        $mockKeysResponse->method('getStatusCode')->willReturn(200);
        $mockKeysResponse->method('getBody')->willReturn($mockKeysStream);

        $mockHttpClient = $this->createStub(ClientInterface::class);
        $mockHttpClient->method('request')->willReturnMap([
            ['GET', $openIDConnectMetadataUrl, [], $mockConfigResponse],
            ['GET', $jwks_uri, [], $mockKeysResponse],
        ]);

        $mockCacheItem = $this->createStub(CacheItemInterface::class);
        $mockCacheItem->method('isHit')->willReturn(false);

        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);
        $mockCacheItemPool->method('getItem')->willReturn($mockCacheItem);

        $provider = new OpenIdConfigurationProvider([
            'openIDConnectMetadataUrl' => $openIDConnectMetadataUrl,
            'cacheItemPool' => $mockCacheItemPool,
            'clientId' => self::CLIENT_ID,
            'clientSecret' => self::CLIENT_SECRET,
            'redirectUri' => self::REDIRECT_URI,
        ], [
            'httpClient' => $mockHttpClient,
        ]);

        $mockJWT = \Mockery::mock('overload:Firebase\JWT\JWT', MockJWT::class);

        $this->expectException(\ItkDev\OpenIdConnect\Exception\DecodeException::class);
        $this->expectExceptionMessage('Error url decoding input');

        $provider->validateIdToken('token', self::NONCE);
    }

    /**
     * Get a mock success response with mock date.
     *
     * @return ResponseInterface
     *                           A success ("200") response with mock body data
     */
    /**
     * Load a JSON fixture from tests/MockData and decode it as an associative
     * array. Fails the test with an explicit message if the file is missing /
     * unreadable / not valid JSON, rather than letting `false` or `null` flow
     * silently into the assertion under test.
     *
     * @return array<string, mixed>
     */
    private function loadMockFixture(string $filename): array
    {
        $path = __DIR__.'/../MockData/'.$filename;
        $contents = file_get_contents($path);
        $this->assertNotFalse($contents, sprintf('Mock fixture not readable: %s', $path));
        $decoded = json_decode($contents, true);
        $this->assertIsArray($decoded, sprintf('Mock fixture is not valid JSON: %s', $path));

        return $decoded;
    }

    private function getMockHttpSuccessResponse(string $mockResponseDataPath): ResponseInterface
    {
        $mockResponseData = file_get_contents(__DIR__.$mockResponseDataPath);

        $mockStream = $this->createStub(StreamInterface::class);
        $mockStream->method('getContents')->willReturn($mockResponseData);

        $mockResponse = $this->createStub(ResponseInterface::class);
        $mockResponse->method('getStatusCode')->willReturn(200);
        $mockResponse->method('getBody')->willReturn($mockStream);

        return $mockResponse;
    }

    /**
     * Get a stdClass object of mock claims.
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
