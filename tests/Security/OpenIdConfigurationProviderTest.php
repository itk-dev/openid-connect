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
use ItkDev\OpenIdConnect\Exception\JwksException;
use ItkDev\OpenIdConnect\Exception\MissingParameterException;
use ItkDev\OpenIdConnect\Exception\NegativeCacheDurationException;
use ItkDev\OpenIdConnect\Exception\NegativeLeewayException;
use ItkDev\OpenIdConnect\Exception\ValidationException;
use ItkDev\OpenIdConnect\Security\OpenIdConfigurationProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\RequestFactory;
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
    private const REDIRECT_URI = 'https://app.example.org';
    private const NONCE = '12345678';

    // Mirrors OpenIdConfigurationProvider::MAX_JSON_RESOURCE_BYTES, which is
    // private. Asserting the boundary needs the exact value.
    private const MAX_JSON_RESOURCE_BYTES = 1048576;

    private OpenIdConfigurationProvider $provider;

    public function setUp(): void
    {
        parent::setUp();

        $openIDConnectMetadataUrl = 'https://provider.example.org/openid-configuration';
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
            'openIDConnectMetadataUrl' => 'https://provider.example.org/openid-configuration',
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
            'openIDConnectMetadataUrl' => 'https://provider.example.org/openid-configuration',
            'leeway' => -10,
        ], []);
    }

    public function testConstructZeroCacheDurationAndLeewayAccepted(): void
    {
        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);

        // Zero is a valid boundary value for both options: cache nothing,
        // tolerate no clock skew. Only negative values are rejected.
        $provider = new OpenIdConfigurationProvider([
            'cacheItemPool' => $mockCacheItemPool,
            'openIDConnectMetadataUrl' => 'https://provider.example.org/openid-configuration',
            'cacheDuration' => 0,
            'leeway' => 0,
        ], []);

        $this->assertInstanceOf(OpenIdConfigurationProvider::class, $provider);
    }

    public function testConstructWiresJwtCollaboratorAsRequestFactory(): void
    {
        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);
        $requestFactory = new RequestFactory();

        $provider = new OpenIdConfigurationProvider([
            'cacheItemPool' => $mockCacheItemPool,
            'openIDConnectMetadataUrl' => 'https://provider.example.org/openid-configuration',
        ], [
            'jwt' => $requestFactory,
        ]);

        // The 'jwt' collaborator must become the provider's request factory;
        // without the explicit wiring the parent's default factory would be
        // silently used instead.
        $this->assertSame($requestFactory, $provider->getRequestFactory());
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

    /**
     * The default length is the entropy of the state parameter, so it is
     * asserted without passing an explicit argument.
     */
    public function testGenerateStateDefaultsTo32Characters(): void
    {
        $state = $this->provider->generateState();

        $this->assertSame(32, strlen($state));
        $this->assertSame($state, $this->provider->getState());
    }

    /**
     * As above, for the nonce.
     */
    public function testGenerateNonceDefaultsTo32Characters(): void
    {
        $this->assertSame(32, strlen($this->provider->generateNonce()));
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
        $mockJWT = $this->overloadJwt();
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

    /**
     * The configured leeway must reach firebase/php-jwt. It travels through the
     * process-global JWT::$leeway, which is why MockJWT declares that static —
     * asserting it here is what pins decodeWithLeeway() to writing the
     * provider's value rather than leaving whatever was there before.
     */
    public function testValidateIdTokenAppliesConfiguredLeeway(): void
    {
        MockJWT::$leeway = 5;

        $observedDuringDecode = null;
        $mockClaims = $this->getMockClaims();

        $mockJWT = $this->overloadJwt();
        $mockJWT->shouldReceive('decode')->andReturnUsing(
            function () use (&$observedDuringDecode, $mockClaims): \stdClass {
                $observedDuringDecode = MockJWT::$leeway;

                return $mockClaims;
            }
        );

        $this->provider->validateIdToken('token', self::NONCE);

        // 30 is the leeway the provider is constructed with in setUp().
        $this->assertSame(30, $observedDuringDecode, 'Configured leeway must be in effect for the decode');
        $this->assertSame(5, MockJWT::$leeway, 'Any pre-existing leeway must be restored afterwards');
    }

    /**
     * The static is restored even when the decode throws, so a rejected token
     * cannot leave this library's leeway applied to the rest of the process.
     */
    public function testValidateIdTokenRestoresLeewayWhenDecodeFails(): void
    {
        MockJWT::$leeway = 5;

        $mockJWT = $this->overloadJwt();
        $mockJWT->shouldReceive('decode')->andThrow(SignatureInvalidException::class, 'Signature verification failed');

        try {
            $this->provider->validateIdToken('token', self::NONCE);
            $this->fail('Expected ValidationException was not thrown');
        } catch (ValidationException) {
            $this->assertSame(5, MockJWT::$leeway, 'Leeway must be restored on the failure path too');
        }
    }

    public function testValidateIdTokenFailure(): void
    {
        $mockJWT = $this->overloadJwt();
        $mockJWT->shouldReceive('decode')->andThrow(SignatureInvalidException::class, 'Signature verification failed');

        try {
            $this->provider->validateIdToken('token', self::NONCE);
        } catch (ValidationException $thrown) {
            $this->assertSame('ID token validation failed: Signature verification failed', $thrown->getMessage());
            $this->assertSame(0, $thrown->getCode());
            $this->assertInstanceOf(SignatureInvalidException::class, $thrown->getPrevious(), 'Original cause must be chained');

            return;
        }
        $this->fail('Expected ValidationException');
    }

    public function testValidateIdTokenAudience(): void
    {
        $mockJWT = $this->overloadJwt();
        $mockClaims = $this->getMockClaims();
        $mockClaims->aud = 'incorrect aud';

        $mockJWT->shouldReceive('decode')->andReturn($mockClaims);

        $this->expectException(ClaimsException::class);
        $this->expectExceptionMessage('ID token has incorrect audience(s): incorrect aud');

        $this->provider->validateIdToken('token', self::NONCE);
    }

    public function testValidateIdTokenIssuer(): void
    {
        $mockJWT = $this->overloadJwt();
        $mockClaims = $this->getMockClaims();
        $mockClaims->iss = 'incorrect iss';

        $mockJWT->shouldReceive('decode')->andReturn($mockClaims);

        $this->expectException(ClaimsException::class);
        $this->expectExceptionMessage('ID token has incorrect issuer: incorrect iss');

        $this->provider->validateIdToken('token', self::NONCE);
    }

    public function testValidateIdTokenNonce(): void
    {
        $mockJWT = $this->overloadJwt();
        $mockClaims = $this->getMockClaims();
        $mockClaims->nonce = 'incorrect nonce';

        $mockJWT->shouldReceive('decode')->andReturn($mockClaims);

        $this->expectException(ClaimsException::class);
        $this->expectExceptionMessage('ID token has incorrect nonce: incorrect nonce');

        $this->provider->validateIdToken('token', self::NONCE);
    }

    /**
     * OIDC Core §2 makes "exp" REQUIRED, and firebase/php-jwt validates it only
     * when present — so a token without it would never expire.
     */
    public function testValidateIdTokenRequiresExpClaim(): void
    {
        $mockJWT = $this->overloadJwt();
        $mockClaims = $this->getMockClaims();
        unset($mockClaims->exp);

        $mockJWT->shouldReceive('decode')->andReturn($mockClaims);

        $this->expectException(ClaimsException::class);
        $this->expectExceptionMessage('ID token missing required numeric "exp" claim (OIDC Core §2)');

        $this->provider->validateIdToken('token', self::NONCE);
    }

    public function testValidateIdTokenRequiresNumericExpClaim(): void
    {
        $mockJWT = $this->overloadJwt();
        $mockClaims = $this->getMockClaims();
        $mockClaims->exp = 'not-a-timestamp';

        $mockJWT->shouldReceive('decode')->andReturn($mockClaims);

        $this->expectException(ClaimsException::class);
        $this->expectExceptionMessage('ID token missing required numeric "exp" claim (OIDC Core §2)');

        $this->provider->validateIdToken('token', self::NONCE);
    }

    public function testValidateIdTokenRequiresIatClaim(): void
    {
        $mockJWT = $this->overloadJwt();
        $mockClaims = $this->getMockClaims();
        unset($mockClaims->iat);

        $mockJWT->shouldReceive('decode')->andReturn($mockClaims);

        $this->expectException(ClaimsException::class);
        $this->expectExceptionMessage('ID token missing required numeric "iat" claim (OIDC Core §2)');

        $this->provider->validateIdToken('token', self::NONCE);
    }

    /**
     * A non-string issuer used to reach string concatenation in the exception
     * message, turning a claims mismatch into an "Array to string conversion".
     */
    public function testValidateIdTokenRequiresStringIssuer(): void
    {
        $mockJWT = $this->overloadJwt();
        $mockClaims = $this->getMockClaims();
        $mockClaims->iss = ['not', 'a', 'string'];

        $mockJWT->shouldReceive('decode')->andReturn($mockClaims);

        $this->expectException(ClaimsException::class);
        $this->expectExceptionMessage('ID token missing required string "iss" claim');

        $this->provider->validateIdToken('token', self::NONCE);
    }

    /**
     * As above for the nonce, which also guards hash_equals() against a
     * non-string second argument.
     */
    public function testValidateIdTokenRequiresStringNonce(): void
    {
        $mockJWT = $this->overloadJwt();
        $mockClaims = $this->getMockClaims();
        $mockClaims->nonce = null;

        $mockJWT->shouldReceive('decode')->andReturn($mockClaims);

        $this->expectException(ClaimsException::class);
        $this->expectExceptionMessage('ID token missing required string "nonce" claim');

        $this->provider->validateIdToken('token', self::NONCE);
    }

    public function testValidateIdTokenRejectsEmptyNonce(): void
    {
        $mockJWT = $this->overloadJwt();
        $mockClaims = $this->getMockClaims();
        $mockClaims->nonce = '';

        $mockJWT->shouldReceive('decode')->andReturn($mockClaims);

        $this->expectException(ClaimsException::class);
        $this->expectExceptionMessage('ID token missing required string "nonce" claim');

        $this->provider->validateIdToken('token', self::NONCE);
    }

    /**
     * Audience matching is a strict comparison. PHP's loose comparison treats
     * numeric strings as equal by value, so an IdP announcing an audience of
     * "1e2" would otherwise satisfy a client id of "100".
     */
    public function testValidateIdTokenComparesAudienceStrictly(): void
    {
        $provider = $this->createProviderWithConfigurationOverrides([], clientId: '100');

        $mockJWT = $this->overloadJwt();
        $mockClaims = $this->getMockClaims();
        $mockClaims->aud = '1e2';

        $mockJWT->shouldReceive('decode')->andReturn($mockClaims);

        $this->expectException(ClaimsException::class);
        $this->expectExceptionMessage('ID token has incorrect audience(s): 1e2');

        $provider->validateIdToken('token', self::NONCE);
    }

    /**
     * A non-string audience entry cannot match a string client id, and must not
     * reach the exception message either.
     */
    public function testValidateIdTokenIgnoresNonStringAudienceEntries(): void
    {
        $mockJWT = $this->overloadJwt();
        $mockClaims = $this->getMockClaims();
        $mockClaims->aud = [['nested'], self::CLIENT_ID];

        $mockJWT->shouldReceive('decode')->andReturn($mockClaims);

        /** @var object{aud: list<mixed>} $claims */
        $claims = $this->provider->validateIdToken('token', self::NONCE);

        $this->assertSame([['nested'], self::CLIENT_ID], $claims->aud);
    }

    /**
     * With every audience entry non-string there is nothing to match, and the
     * message must stay printable — interpolating the raw list would render an
     * "Array to string conversion" instead of naming the audiences.
     */
    public function testValidateIdTokenKeepsAudienceMessagePrintable(): void
    {
        $mockJWT = $this->overloadJwt();
        $mockClaims = $this->getMockClaims();
        $mockClaims->aud = [['nested']];

        $mockJWT->shouldReceive('decode')->andReturn($mockClaims);

        try {
            $this->provider->validateIdToken('token', self::NONCE);
            $this->fail('Expected ClaimsException was not thrown');
        } catch (ClaimsException $thrown) {
            $this->assertSame('ID token has incorrect audience(s): ', $thrown->getMessage());
        }
    }

    public function testConstructBadUrl(): void
    {
        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);

        $this->expectException(BadUrlException::class);
        $this->expectExceptionMessage('OpenIDConnectMetadataUrl is invalid: not-a-valid-url');

        new OpenIdConfigurationProvider([
            'cacheItemPool' => $mockCacheItemPool,
            'openIDConnectMetadataUrl' => 'not-a-valid-url',
        ], []);
    }

    public function testConstructHttpUrlNotAllowed(): void
    {
        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);

        $this->expectException(IllegalSchemeException::class);
        $this->expectExceptionMessage('OpenIDConnectMetadataUrl must use https: http://provider.example.org/openid-configuration');

        new OpenIdConfigurationProvider([
            'cacheItemPool' => $mockCacheItemPool,
            'openIDConnectMetadataUrl' => 'http://provider.example.org/openid-configuration',
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
            'openIDConnectMetadataUrl' => 'http://provider.example.org/openid-configuration',
            'allowHttp' => true,
            'clientId' => self::CLIENT_ID,
            'clientSecret' => self::CLIENT_SECRET,
            'redirectUri' => self::REDIRECT_URI,
        ], [
            'httpClient' => $mockHttpClient,
        ]);

        $this->assertInstanceOf(OpenIdConfigurationProvider::class, $provider);
    }

    public function testConstructAcceptsUppercaseHttpsScheme(): void
    {
        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);

        $provider = new OpenIdConfigurationProvider([
            'cacheItemPool' => $mockCacheItemPool,
            'openIDConnectMetadataUrl' => 'HTTPS://provider.example.org/openid-configuration',
        ], []);

        $this->assertInstanceOf(OpenIdConfigurationProvider::class, $provider);
    }

    public function testDiscoveredAuthorizationEndpointMustUseHttps(): void
    {
        $provider = $this->createProviderWithConfigurationOverrides([
            'authorization_endpoint' => 'http://provider.example.org/oauth2/v2.0/authorize',
        ]);

        $this->expectException(IllegalSchemeException::class);
        $this->expectExceptionMessage('OIDC discovery document "authorization_endpoint" must use https: http://provider.example.org/oauth2/v2.0/authorize');

        $provider->getBaseAuthorizationUrl();
    }

    public function testDiscoveredTokenEndpointMustUseHttps(): void
    {
        $provider = $this->createProviderWithConfigurationOverrides([
            'token_endpoint' => 'http://provider.example.org/oauth2/v2.0/token',
        ]);

        $this->expectException(IllegalSchemeException::class);
        $this->expectExceptionMessage('OIDC discovery document "token_endpoint" must use https: http://provider.example.org/oauth2/v2.0/token');

        $provider->getBaseAccessTokenUrl([]);
    }

    /**
     * The load-bearing case: the code exchange posts the client secret, so a
     * discovery document announcing a plain-http token endpoint must fail
     * before the request goes out.
     */
    public function testIdTokenExchangeRefusesHttpTokenEndpoint(): void
    {
        $provider = $this->createProviderWithConfigurationOverrides([
            'token_endpoint' => 'http://provider.example.org/oauth2/v2.0/token',
        ]);

        $this->expectException(IllegalSchemeException::class);
        $this->expectExceptionMessage('OIDC discovery document "token_endpoint" must use https: http://provider.example.org/oauth2/v2.0/token');

        $provider->getIdToken('test-code');
    }

    public function testDiscoveredUserinfoEndpointMustUseHttps(): void
    {
        $provider = $this->createProviderWithConfigurationOverrides([
            'userinfo_endpoint' => 'http://provider.example.org/openid/userinfo',
        ]);

        $this->expectException(IllegalSchemeException::class);
        $this->expectExceptionMessage('OIDC discovery document "userinfo_endpoint" must use https: http://provider.example.org/openid/userinfo');

        $provider->getResourceOwnerDetailsUrl($this->createStub(AccessToken::class));
    }

    public function testDiscoveredEndSessionEndpointMustUseHttps(): void
    {
        $provider = $this->createProviderWithConfigurationOverrides([
            'end_session_endpoint' => 'http://provider.example.org/oauth2/v2.0/logout',
        ]);

        $this->expectException(IllegalSchemeException::class);
        $this->expectExceptionMessage('OIDC discovery document "end_session_endpoint" must use https: http://provider.example.org/oauth2/v2.0/logout');

        $provider->getEndSessionUrl();
    }

    /**
     * The JWKS URI decides which keys sign-off on identities, so it is held to
     * the same scheme policy. `getJwtVerificationKeys()` refuses before the
     * fetch, hence no JWT decode is reached.
     */
    public function testJwksFetchRefusesHttpJwksUri(): void
    {
        $provider = $this->createProviderWithConfigurationOverrides([
            'jwks_uri' => 'http://provider.example.org/discovery/v2.0/keys',
        ]);

        $this->expectException(IllegalSchemeException::class);
        $this->expectExceptionMessage('OIDC discovery document "jwks_uri" must use https: http://provider.example.org/discovery/v2.0/keys');

        $provider->validateIdToken('token', self::NONCE);
    }

    public function testDiscoveredHttpEndpointsAreAllowedWithAllowHttp(): void
    {
        $provider = $this->createProviderWithConfigurationOverrides([
            'authorization_endpoint' => 'http://provider.example.org/oauth2/v2.0/authorize',
            'token_endpoint' => 'http://provider.example.org/oauth2/v2.0/token',
            'userinfo_endpoint' => 'http://provider.example.org/openid/userinfo',
            'end_session_endpoint' => 'http://provider.example.org/oauth2/v2.0/logout',
        ], allowHttp: true);

        $this->assertSame('http://provider.example.org/oauth2/v2.0/authorize', $provider->getBaseAuthorizationUrl());
        $this->assertSame('http://provider.example.org/oauth2/v2.0/token', $provider->getBaseAccessTokenUrl([]));
        $this->assertSame('http://provider.example.org/openid/userinfo', $provider->getResourceOwnerDetailsUrl($this->createStub(AccessToken::class)));
        $this->assertSame('http://provider.example.org/oauth2/v2.0/logout', $provider->getEndSessionUrl());
    }

    public function testDiscoveredEndpointAcceptsUppercaseHttpsScheme(): void
    {
        $provider = $this->createProviderWithConfigurationOverrides([
            'authorization_endpoint' => 'HTTPS://provider.example.org/oauth2/v2.0/authorize',
        ]);

        $this->assertSame('HTTPS://provider.example.org/oauth2/v2.0/authorize', $provider->getBaseAuthorizationUrl());
    }

    public function testDiscoveredEndpointWithoutSchemeIsRejected(): void
    {
        $provider = $this->createProviderWithConfigurationOverrides([
            'authorization_endpoint' => '/oauth2/v2.0/authorize',
        ]);

        $this->expectException(BadUrlException::class);
        $this->expectExceptionMessage('OIDC discovery document "authorization_endpoint" is invalid: /oauth2/v2.0/authorize');

        $provider->getBaseAuthorizationUrl();
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

        try {
            $method->invoke($this->provider, $response, []);
        } catch (IdentityProviderException $thrown) {
            $this->assertSame('400', $thrown->getMessage());
            $this->assertSame(0, $thrown->getCode());

            return;
        }
        $this->fail('Expected IdentityProviderException');
    }

    public function testCreateResourceOwner(): void
    {
        $token = $this->createStub(AccessToken::class);

        $method = new \ReflectionMethod(OpenIdConfigurationProvider::class, 'createResourceOwner');

        $owner = $method->invoke($this->provider, ['id' => '123', 'name' => 'Test'], $token);
        $this->assertInstanceOf(\League\OAuth2\Client\Provider\ResourceOwnerInterface::class, $owner);
        $this->assertSame('123', $owner->getId());
    }

    public function testValidateIdTokenArrayAudience(): void
    {
        $mockJWT = $this->overloadJwt();
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
        $mockJWT = $this->overloadJwt();
        $mockClaims = $this->getMockClaims();
        $mockClaims->aud = ['wrong_client_1', 'wrong_client_2'];

        $mockJWT->shouldReceive('decode')->andReturn($mockClaims);

        $this->expectException(ClaimsException::class);
        $this->expectExceptionMessage('ID token has incorrect audience(s): wrong_client_1, wrong_client_2');

        $this->provider->validateIdToken('token', self::NONCE);
    }

    public function testGetIdTokenSuccess(): void
    {
        $tokenEndpoint = 'https://azure_b2c_test.b2clogin.com/azure_b2c_test.onmicrosoft.com/oauth2/v2.0/token?p=test-policy';
        $openIDConnectMetadataUrl = 'https://provider.example.org/openid-configuration';
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
        $openIDConnectMetadataUrl = 'https://provider.example.org/openid-configuration';

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

        try {
            $provider->getIdToken('test-code');
        } catch (CodeException $thrown) {
            $this->assertSame('Get ID token failed: Connection failed', $thrown->getMessage());
            $this->assertSame(0, $thrown->getCode());
            $this->assertInstanceOf(ClientExceptionInterface::class, $thrown->getPrevious(), 'Original cause must be chained');

            return;
        }
        $this->fail('Expected CodeException');
    }

    public function testGetIdTokenRejectsInvalidJsonResponse(): void
    {
        $tokenEndpoint = 'https://azure_b2c_test.b2clogin.com/azure_b2c_test.onmicrosoft.com/oauth2/v2.0/token?p=test-policy';
        $openIDConnectMetadataUrl = 'https://provider.example.org/openid-configuration';

        $mockConfigResponse = $this->getMockHttpSuccessResponse('/../MockData/mockOpenIDConfiguration.json');

        $malformedTokenResponseBody = 'not valid json{{{';
        $mockTokenStream = $this->createStub(StreamInterface::class);
        $mockTokenStream->method('getContents')->willReturn($malformedTokenResponseBody);
        $mockTokenStream->method('__toString')->willReturn($malformedTokenResponseBody);

        $mockTokenResponse = $this->createStub(ResponseInterface::class);
        $mockTokenResponse->method('getStatusCode')->willReturn(200);
        $mockTokenResponse->method('getBody')->willReturn($mockTokenStream);

        $mockHttpClient = $this->createStub(ClientInterface::class);
        $mockHttpClient->method('request')->willReturnMap([
            ['GET', $openIDConnectMetadataUrl, [], $mockConfigResponse],
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

        try {
            $provider->getIdToken('test-code');
        } catch (CodeException $thrown) {
            $this->assertSame(0, $thrown->getCode());
            $this->assertInstanceOf(\JsonException::class, $thrown->getPrevious(), 'Original cause must be chained');

            return;
        }
        $this->fail('Expected CodeException');
    }

    public function testGetIdTokenRejectsResponseWithoutStringIdToken(): void
    {
        $tokenEndpoint = 'https://azure_b2c_test.b2clogin.com/azure_b2c_test.onmicrosoft.com/oauth2/v2.0/token?p=test-policy';
        $openIDConnectMetadataUrl = 'https://provider.example.org/openid-configuration';

        $mockConfigResponse = $this->getMockHttpSuccessResponse('/../MockData/mockOpenIDConfiguration.json');

        // Spec-compliant token endpoint returns JSON with `id_token`.
        // Here the IdP returns a JSON object that's missing it entirely.
        $malformedTokenResponseBody = (string) json_encode(['access_token' => 'not-an-id-token']);
        $mockTokenStream = $this->createStub(StreamInterface::class);
        $mockTokenStream->method('getContents')->willReturn($malformedTokenResponseBody);
        $mockTokenStream->method('__toString')->willReturn($malformedTokenResponseBody);

        $mockTokenResponse = $this->createStub(ResponseInterface::class);
        $mockTokenResponse->method('getStatusCode')->willReturn(200);
        $mockTokenResponse->method('getBody')->willReturn($mockTokenStream);

        $mockHttpClient = $this->createStub(ClientInterface::class);
        $mockHttpClient->method('request')->willReturnMap([
            ['GET', $openIDConnectMetadataUrl, [], $mockConfigResponse],
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

        $this->expectException(CodeException::class);
        $this->expectExceptionMessage('Token endpoint response missing string "id_token"');

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
            'openIDConnectMetadataUrl' => 'https://provider.example.org/openid-configuration',
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

    /**
     * A PSR-6 pool round-trips serialized values, so an entry written by
     * another code path (or an older version of this library) can come back as
     * an object rather than an array. The `(array)` cast in `getConfiguration()`
     * absorbs that; without it PHP raises "Cannot use object of type stdClass
     * as array" — a bare `\Error`, which is not part of the library's exception
     * contract.
     */
    public function testGetConfigurationCacheHitWithObjectPayload(): void
    {
        $configuration = $this->loadMockFixture('mockOpenIDConfiguration.json');

        $mockCacheItem = $this->createStub(CacheItemInterface::class);
        $mockCacheItem->method('isHit')->willReturn(true);
        $mockCacheItem->method('get')->willReturn((object) $configuration);

        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);
        $mockCacheItemPool->method('getItem')->willReturn($mockCacheItem);

        $mockHttpClient = $this->createStub(ClientInterface::class);

        $provider = new OpenIdConfigurationProvider([
            'openIDConnectMetadataUrl' => 'https://provider.example.org/openid-configuration',
            'cacheItemPool' => $mockCacheItemPool,
            'clientId' => self::CLIENT_ID,
            'clientSecret' => self::CLIENT_SECRET,
            'redirectUri' => self::REDIRECT_URI,
        ], [
            'httpClient' => $mockHttpClient,
        ]);

        $this->assertSame($configuration['authorization_endpoint'], $provider->getBaseAuthorizationUrl());
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
            'openIDConnectMetadataUrl' => 'https://provider.example.org/openid-configuration',
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
        $openIDConnectMetadataUrl = 'https://provider.example.org/openid-configuration';

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
        $this->expectExceptionMessage('Cannot access json resource: https://provider.example.org/openid-configuration');

        $provider->getBaseAuthorizationUrl();
    }

    public function testFetchJsonResourceClientException(): void
    {
        $openIDConnectMetadataUrl = 'https://provider.example.org/openid-configuration';

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

        try {
            $provider->getBaseAuthorizationUrl();
        } catch (HttpException $thrown) {
            $this->assertSame('Connection refused', $thrown->getMessage());
            $this->assertSame(0, $thrown->getCode());
            $this->assertSame($exception, $thrown->getPrevious(), 'Original cause must be chained');

            return;
        }
        $this->fail('Expected HttpException');
    }

    /**
     * A body one byte over the limit is refused. Exercised through a response
     * that reports no size, so it is the retrieved content that trips the cap.
     */
    public function testFetchJsonResourceRejectsOversizedContent(): void
    {
        $provider = $this->createProviderWithMetadataBody($this->discoveryDocumentOfExactByteSize(self::MAX_JSON_RESOURCE_BYTES + 1));

        $this->expectException(HttpException::class);
        $this->expectExceptionMessage(sprintf(
            'Json resource is larger than the %d byte limit (%d bytes): https://provider.example.org/openid-configuration',
            self::MAX_JSON_RESOURCE_BYTES,
            self::MAX_JSON_RESOURCE_BYTES + 1,
        ));

        $provider->getBaseAuthorizationUrl();
    }

    /**
     * A body of exactly the limit is accepted and still parsed. Paired with the
     * test above, this pins the comparison to the byte rather than leaving the
     * boundary free.
     */
    public function testFetchJsonResourceAcceptsContentAtTheLimit(): void
    {
        $provider = $this->createProviderWithMetadataBody($this->discoveryDocumentOfExactByteSize(self::MAX_JSON_RESOURCE_BYTES));

        $this->assertSame(
            'https://azure_b2c_test.b2clogin.com/azure_b2c_test.onmicrosoft.com/oauth2/v2.0/authorize?p=test-policy',
            $provider->getBaseAuthorizationUrl()
        );
    }

    /**
     * Where the response declares its size, that is checked before the body is
     * retrieved at all — a chunked response declares none, which is why the
     * content is checked too.
     */
    public function testFetchJsonResourceRejectsOversizedDeclaredSize(): void
    {
        $provider = $this->createProviderWithMetadataBody('{}', self::MAX_JSON_RESOURCE_BYTES + 1);

        $this->expectException(HttpException::class);
        $this->expectExceptionMessage(sprintf(
            'Json resource is larger than the %d byte limit (%d bytes): https://provider.example.org/openid-configuration',
            self::MAX_JSON_RESOURCE_BYTES,
            self::MAX_JSON_RESOURCE_BYTES + 1,
        ));

        $provider->getBaseAuthorizationUrl();
    }

    public function testFetchJsonResourceAcceptsDeclaredSizeAtTheLimit(): void
    {
        $provider = $this->createProviderWithMetadataBody(
            $this->discoveryDocumentOfExactByteSize(self::MAX_JSON_RESOURCE_BYTES),
            self::MAX_JSON_RESOURCE_BYTES,
        );

        $this->assertSame(
            'https://azure_b2c_test.b2clogin.com/azure_b2c_test.onmicrosoft.com/oauth2/v2.0/authorize?p=test-policy',
            $provider->getBaseAuthorizationUrl()
        );
    }

    public function testFetchJsonResourceInvalidJson(): void
    {
        $openIDConnectMetadataUrl = 'https://provider.example.org/openid-configuration';

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

        try {
            $provider->getBaseAuthorizationUrl();
        } catch (\ItkDev\OpenIdConnect\Exception\JsonException $thrown) {
            $this->assertSame(0, $thrown->getCode());
            $this->assertInstanceOf(\JsonException::class, $thrown->getPrevious(), 'Original cause must be chained');

            return;
        }
        $this->fail('Expected JsonException');
    }

    public function testGetJwtVerificationKeysRejectsJwksMissingKeysArray(): void
    {
        $provider = $this->createProviderWithCustomJwks((string) json_encode(['something_else' => 1]));
        $this->overloadJwt();

        $this->expectException(JwksException::class);
        $this->expectExceptionMessage('JWKS payload missing array "keys" property (RFC 7517 §5)');

        $provider->validateIdToken('token', self::NONCE);
    }

    public function testGetJwtVerificationKeysRejectsNonObjectJwkEntry(): void
    {
        $provider = $this->createProviderWithCustomJwks((string) json_encode(['keys' => [42]]));
        $this->overloadJwt();

        $this->expectException(JwksException::class);
        $this->expectExceptionMessage('JWK entry is not a JSON object');

        $provider->validateIdToken('token', self::NONCE);
    }

    public function testGetJwtVerificationKeysRejectsNonStringKty(): void
    {
        $provider = $this->createProviderWithCustomJwks(
            (string) json_encode(['keys' => [['kid' => 'key-1', 'kty' => 42]]]),
        );
        $this->overloadJwt();

        $this->expectException(JwksException::class);
        $this->expectExceptionMessage('JWK entry missing string "kty" for key id: key-1');

        $provider->validateIdToken('token', self::NONCE);
    }

    public function testGetJwtVerificationKeysRejectsRsaWithoutStringExpOrModulus(): void
    {
        $provider = $this->createProviderWithCustomJwks(
            (string) json_encode(['keys' => [['kid' => 'key-1', 'kty' => 'RSA', 'e' => 42, 'n' => 'abc']]]),
        );
        $this->overloadJwt();

        $this->expectException(JwksException::class);
        $this->expectExceptionMessage('JWK RSA entry missing string "e"/"n" for key id: key-1');

        $provider->validateIdToken('token', self::NONCE);
    }

    /**
     * An exponent of whitespace is a string, and base64-decodes to zero bytes,
     * so it clears the is_string guard and reaches the key conversion. The
     * emptiness check has to sit after the decode for exactly this reason.
     */
    public function testGetJwtVerificationKeysRejectsRsaWithEmptyExponent(): void
    {
        $provider = $this->createProviderWithCustomJwks(
            (string) json_encode(['keys' => [['kid' => 'key-1', 'kty' => 'RSA', 'e' => ' ', 'n' => 'abc']]]),
        );
        $this->overloadJwt();

        $this->expectException(JwksException::class);
        $this->expectExceptionMessage('JWK RSA entry has empty "e"/"n" for key id: key-1');

        $provider->validateIdToken('token', self::NONCE);
    }

    /**
     * As above, for the modulus.
     */
    public function testGetJwtVerificationKeysRejectsRsaWithEmptyModulus(): void
    {
        $provider = $this->createProviderWithCustomJwks(
            (string) json_encode(['keys' => [['kid' => 'key-1', 'kty' => 'RSA', 'e' => 'AQAB', 'n' => '']]]),
        );
        $this->overloadJwt();

        $this->expectException(JwksException::class);
        $this->expectExceptionMessage('JWK RSA entry has empty "e"/"n" for key id: key-1');

        $provider->validateIdToken('token', self::NONCE);
    }

    /**
     * An IdP publishing a private key clears every guard here — `kty` is RSA and
     * `n`/`e` are well-formed — and is refused by `JWK::parseKey()` instead. The
     * refusal must arrive as a `JwksException` with the cause chained, not as
     * firebase's own `UnexpectedValueException`.
     */
    public function testGetJwtVerificationKeysWrapsUnusableKey(): void
    {
        $fixtureKeys = $this->loadMockFixture('mockOpenIDValidationKeys.json');
        $this->assertIsArray($fixtureKeys['keys']);
        $this->assertIsArray($fixtureKeys['keys'][0]);
        $key = $fixtureKeys['keys'][0];
        $kid = $key['kid'];
        $this->assertIsString($kid);

        $key['d'] = 'private-key-material';

        $provider = $this->createProviderWithCustomJwks((string) json_encode(['keys' => [$key]]));
        $this->overloadJwt();

        try {
            $provider->validateIdToken('token', self::NONCE);
            $this->fail('Expected JwksException was not thrown');
        } catch (JwksException $thrown) {
            $this->assertSame(
                sprintf('JWK entry for key id %s is not a usable key: RSA private keys are not supported', $kid),
                $thrown->getMessage()
            );
            $this->assertSame(0, $thrown->getCode());
            $this->assertInstanceOf(\UnexpectedValueException::class, $thrown->getPrevious(), 'Original cause must be chained');
        }
    }

    /**
     * RFC 7517 §5 allows a JWK Set to carry members besides "keys". The document
     * is now cached whole, so those members must survive the round trip — and
     * "keys" is not necessarily the first of them.
     */
    public function testGetJwksDocumentKeepsAdditionalTopLevelMembers(): void
    {
        $fixtureKeys = $this->loadMockFixture('mockOpenIDValidationKeys.json');
        $this->assertIsArray($fixtureKeys['keys']);

        $provider = $this->createProviderWithCustomJwks(
            (string) json_encode(['extra_member' => 'ignored', 'keys' => $fixtureKeys['keys']]),
        );
        $mockJWT = $this->overloadJwt();
        $mockJWT->shouldReceive('decode')->andReturn($this->getMockClaims());

        /** @var object{nonce: string} $claims */
        $claims = $provider->validateIdToken('token', self::NONCE);
        $this->assertSame(self::NONCE, $claims->nonce);
    }

    public function testGetJwtVerificationKeysRejectsNonStringKid(): void
    {
        $openIDConnectMetadataUrl = 'https://provider.example.org/openid-configuration';
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

        $mockJWT = $this->overloadJwt();

        $this->expectException(JwksException::class);
        $this->expectExceptionMessage('JWK entry missing string "kid" (RFC 7517 §4.5)');

        $provider->validateIdToken('token', self::NONCE);
    }

    public function testGetJwtVerificationKeysUnsupportedKeyType(): void
    {
        $openIDConnectMetadataUrl = 'https://provider.example.org/openid-configuration';
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

        $mockJWT = $this->overloadJwt();

        $this->expectException(JwksException::class);
        $this->expectExceptionMessage('Unsupported key data for key id: ec-key-1');

        $provider->validateIdToken('token', self::NONCE);
    }

    public function testGetJwtVerificationKeysCacheHit(): void
    {
        $openIDConnectMetadataUrl = 'https://provider.example.org/openid-configuration';

        $configuration = $this->loadMockFixture('mockOpenIDConfiguration.json');

        $cachedJwks = $this->loadMockFixture('mockOpenIDValidationKeys.json');

        $configCacheItem = $this->createStub(CacheItemInterface::class);
        $configCacheItem->method('isHit')->willReturn(true);
        $configCacheItem->method('get')->willReturn($configuration);

        $jwksCacheItem = $this->createStub(CacheItemInterface::class);
        $jwksCacheItem->method('isHit')->willReturn(true);
        $jwksCacheItem->method('get')->willReturn($cachedJwks);

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

        $mockJWT = $this->overloadJwt();
        $mockClaims = $this->getMockClaims();
        $mockJWT->shouldReceive('decode')->andReturn($mockClaims);

        /** @var object{nonce: string} $claims */
        $claims = $provider->validateIdToken('token', self::NONCE);
        $this->assertEquals(self::NONCE, $claims->nonce);
    }

    /**
     * As for the discovery document, a cached JWKS document can come back as an
     * object. The `(array)` cast in `getJwksDocument()` absorbs it; without the
     * cast the method returns an object from an `: array` return type and PHP
     * raises a `TypeError`.
     */
    public function testGetJwtVerificationKeysCacheHitWithObjectPayload(): void
    {
        $openIDConnectMetadataUrl = 'https://provider.example.org/openid-configuration';

        $configCacheItem = $this->createStub(CacheItemInterface::class);
        $configCacheItem->method('isHit')->willReturn(true);
        $configCacheItem->method('get')->willReturn($this->loadMockFixture('mockOpenIDConfiguration.json'));

        $jwksCacheItem = $this->createStub(CacheItemInterface::class);
        $jwksCacheItem->method('isHit')->willReturn(true);
        $jwksCacheItem->method('get')->willReturn((object) $this->loadMockFixture('mockOpenIDValidationKeys.json'));

        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);
        $mockCacheItemPool->method('getItem')->willReturnCallback(
            fn (string $key) => str_contains($key, 'jwks') ? $jwksCacheItem : $configCacheItem
        );

        $provider = new OpenIdConfigurationProvider([
            'openIDConnectMetadataUrl' => $openIDConnectMetadataUrl,
            'cacheItemPool' => $mockCacheItemPool,
            'clientId' => self::CLIENT_ID,
            'clientSecret' => self::CLIENT_SECRET,
            'redirectUri' => self::REDIRECT_URI,
        ], [
            'httpClient' => $this->createStub(ClientInterface::class),
        ]);

        $mockJWT = $this->overloadJwt();
        $mockJWT->shouldReceive('decode')->andReturn($this->getMockClaims());

        /** @var object{nonce: string} $claims */
        $claims = $provider->validateIdToken('token', self::NONCE);
        $this->assertEquals(self::NONCE, $claims->nonce);
    }

    public function testGetConfigurationCachesFetchedDocument(): void
    {
        $openIDConnectMetadataUrl = 'https://provider.example.org/openid-configuration';
        $configuration = $this->loadMockFixture('mockOpenIDConfiguration.json');

        $mockConfigResponse = $this->getMockHttpSuccessResponse('/../MockData/mockOpenIDConfiguration.json');
        $mockHttpClient = $this->createStub(ClientInterface::class);
        $mockHttpClient->method('request')->willReturn($mockConfigResponse);

        // On a cache miss the fetched discovery document must be stored with
        // the configured cache duration, under the namespaced cache key.
        $configCacheItem = $this->createMock(CacheItemInterface::class);
        $configCacheItem->method('isHit')->willReturn(false);
        $configCacheItem->expects($this->once())->method('set')->with($configuration)->willReturnSelf();
        $configCacheItem->expects($this->once())->method('expiresAfter')->with(3600)->willReturnSelf();

        $expectedCacheKey = 'itk-openid-connect-configuration-||'.hash('sha1', $openIDConnectMetadataUrl).'||configuration';

        $mockCacheItemPool = $this->createMock(CacheItemPoolInterface::class);
        $mockCacheItemPool->expects($this->once())->method('getItem')->with($expectedCacheKey)->willReturn($configCacheItem);
        $mockCacheItemPool->expects($this->once())->method('save')->with($configCacheItem)->willReturn(true);

        $provider = new OpenIdConfigurationProvider([
            'openIDConnectMetadataUrl' => $openIDConnectMetadataUrl,
            'cacheItemPool' => $mockCacheItemPool,
            'clientId' => self::CLIENT_ID,
            'clientSecret' => self::CLIENT_SECRET,
            'redirectUri' => self::REDIRECT_URI,
            'cacheDuration' => 3600,
        ], [
            'httpClient' => $mockHttpClient,
        ]);

        $authUrl = $provider->getBaseAuthorizationUrl();
        $this->assertSame('https://azure_b2c_test.b2clogin.com/azure_b2c_test.onmicrosoft.com/oauth2/v2.0/authorize?p=test-policy', $authUrl);
    }

    public function testGetJwksDocumentCachesFetchedDocument(): void
    {
        $openIDConnectMetadataUrl = 'https://provider.example.org/openid-configuration';
        $configuration = $this->loadMockFixture('mockOpenIDConfiguration.json');

        $mockKeysResponse = $this->getMockHttpSuccessResponse('/../MockData/mockOpenIDValidationKeys.json');
        $mockHttpClient = $this->createStub(ClientInterface::class);
        $mockHttpClient->method('request')->willReturn($mockKeysResponse);

        $configCacheItem = $this->createStub(CacheItemInterface::class);
        $configCacheItem->method('isHit')->willReturn(true);
        $configCacheItem->method('get')->willReturn($configuration);

        // On a JWKS cache miss the fetched *document* must be stored with the
        // configured cache duration and saved to the pool. The built Key objects
        // are deliberately not cached: JWK::parseKey() wraps an
        // OpenSSLAsymmetricKey, which PHP refuses to serialize.
        $jwksCacheItem = $this->createMock(CacheItemInterface::class);
        $jwksCacheItem->method('isHit')->willReturn(false);
        $jwksCacheItem->expects($this->once())->method('set')
            ->with($this->loadMockFixture('mockOpenIDValidationKeys.json'))
            ->willReturnSelf();
        $jwksCacheItem->expects($this->once())->method('expiresAfter')->with(3600)->willReturnSelf();

        $mockCacheItemPool = $this->createMock(CacheItemPoolInterface::class);
        $mockCacheItemPool->method('getItem')->willReturnCallback(
            static fn (string $key) => str_contains($key, 'jwks') ? $jwksCacheItem : $configCacheItem
        );
        $mockCacheItemPool->expects($this->once())->method('save')->with($jwksCacheItem)->willReturn(true);

        $provider = new OpenIdConfigurationProvider([
            'openIDConnectMetadataUrl' => $openIDConnectMetadataUrl,
            'cacheItemPool' => $mockCacheItemPool,
            'clientId' => self::CLIENT_ID,
            'clientSecret' => self::CLIENT_SECRET,
            'redirectUri' => self::REDIRECT_URI,
            'cacheDuration' => 3600,
        ], [
            'httpClient' => $mockHttpClient,
        ]);

        $mockJWT = $this->overloadJwt();
        $mockJWT->shouldReceive('decode')->andReturn($this->getMockClaims());

        /** @var object{nonce: string} $claims */
        $claims = $provider->validateIdToken('token', self::NONCE);
        $this->assertEquals(self::NONCE, $claims->nonce);
    }

    public function testGetJwtVerificationKeysBuildsAllJwksKeys(): void
    {
        // Two RSA keys in the JWKS: the full key map (not just the first
        // entry) must reach JWT::decode, since the token's "kid" may match
        // any key published by the IdP.
        $fixtureKeys = $this->loadMockFixture('mockOpenIDValidationKeys.json');
        $this->assertIsArray($fixtureKeys['keys']);
        $this->assertIsArray($fixtureKeys['keys'][0]);
        $template = $fixtureKeys['keys'][0];

        $jwks = ['keys' => [
            ['kid' => 'key-a'] + $template,
            ['kid' => 'key-b'] + $template,
        ]];
        $provider = $this->createProviderWithCustomJwks((string) json_encode($jwks));

        $mockJWT = $this->overloadJwt();
        $mockJWT->shouldReceive('decode')->with(
            \Mockery::type('string'),
            \Mockery::on(static fn (array $keys): bool => 2 === count($keys)
                && $keys['key-a'] instanceof Key
                && $keys['key-b'] instanceof Key)
        )->andReturn($this->getMockClaims());

        /** @var object{nonce: string} $claims */
        $claims = $provider->validateIdToken('token', self::NONCE);
        $this->assertEquals(self::NONCE, $claims->nonce);
    }

    public function testGetConfigurationCacheInvalidArgument(): void
    {
        $openIDConnectMetadataUrl = 'https://provider.example.org/openid-configuration';

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

        try {
            $provider->getBaseAuthorizationUrl();
        } catch (CacheException $thrown) {
            $this->assertSame('Invalid cache key', $thrown->getMessage());
            $this->assertSame(0, $thrown->getCode());
            $this->assertSame($exception, $thrown->getPrevious(), 'Original cause must be chained');

            return;
        }
        $this->fail('Expected CacheException');
    }

    public function testGetJwtVerificationKeysCacheInvalidArgument(): void
    {
        $openIDConnectMetadataUrl = 'https://provider.example.org/openid-configuration';
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

        try {
            $provider->validateIdToken('token', self::NONCE);
        } catch (CacheException $thrown) {
            $this->assertSame('Invalid jwks cache key', $thrown->getMessage());
            $this->assertSame(0, $thrown->getCode());
            $this->assertSame($exception, $thrown->getPrevious(), 'Original cause must be chained');

            return;
        }
        $this->fail('Expected CacheException');
    }

    public function testBase64urlDecodeFailure(): void
    {
        $openIDConnectMetadataUrl = 'https://provider.example.org/openid-configuration';
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

        $mockJWT = $this->overloadJwt();

        $this->expectException(\ItkDev\OpenIdConnect\Exception\DecodeException::class);
        $this->expectExceptionMessage('Error url decoding input !!!');

        $provider->validateIdToken('token', self::NONCE);
    }

    /**
     * Get a mock success response with mock date.
     *
     * @return ResponseInterface A success ("200") response with mock body data
     */
    /**
     * Load a JSON fixture from tests/MockData and decode it as an associative
     * array. Fails the test with an explicit message if the file is missing /
     * unreadable / not valid JSON, rather than letting `false` or `null` flow
     * silently into the assertion under test.
     *
     * @return array<mixed> top-level decoded JSON; callers cast / narrow as needed
     */
    /**
     * Overload `Firebase\JWT\JWT` for the duration of the test.
     *
     * Callers stub `decode()` themselves. `urlsafeB64Decode()` has to keep
     * working, because `JWK::parseKey()` — production code, reached while
     * building keys from the JWKS — calls it; overloading the whole class would
     * otherwise take that out along with `decode()`.
     */
    private function overloadJwt(): \Mockery\MockInterface
    {
        /** @var \Mockery\MockInterface $mockJWT */
        $mockJWT = \Mockery::mock('overload:Firebase\JWT\JWT', MockJWT::class);
        $mockJWT->shouldReceive('urlsafeB64Decode')->andReturnUsing(
            static fn (string $input): string => (string) base64_decode(strtr($input, '-_', '+/'), true)
        );

        return $mockJWT;
    }

    /**
     * Build a provider whose metadata URL answers with the given raw body, on a
     * cache miss so the fetch actually happens.
     *
     * @param int|null $declaredSize what the response reports as its body size;
     *                               null models a chunked response
     */
    private function createProviderWithMetadataBody(string $body, ?int $declaredSize = null): OpenIdConfigurationProvider
    {
        $mockStream = $this->createStub(StreamInterface::class);
        $mockStream->method('getContents')->willReturn($body);
        $mockStream->method('getSize')->willReturn($declaredSize);

        $mockResponse = $this->createStub(ResponseInterface::class);
        $mockResponse->method('getStatusCode')->willReturn(200);
        $mockResponse->method('getBody')->willReturn($mockStream);

        $mockHttpClient = $this->createStub(ClientInterface::class);
        $mockHttpClient->method('request')->willReturn($mockResponse);

        $mockCacheItem = $this->createStub(CacheItemInterface::class);
        $mockCacheItem->method('isHit')->willReturn(false);

        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);
        $mockCacheItemPool->method('getItem')->willReturn($mockCacheItem);

        return new OpenIdConfigurationProvider([
            'openIDConnectMetadataUrl' => 'https://provider.example.org/openid-configuration',
            'cacheItemPool' => $mockCacheItemPool,
            'clientId' => self::CLIENT_ID,
            'clientSecret' => self::CLIENT_SECRET,
            'redirectUri' => self::REDIRECT_URI,
        ], [
            'httpClient' => $mockHttpClient,
        ]);
    }

    /**
     * Encode the discovery fixture, padded so the JSON is exactly $bytes long.
     */
    private function discoveryDocumentOfExactByteSize(int $bytes): string
    {
        $configuration = $this->loadMockFixture('mockOpenIDConfiguration.json');
        $configuration['pad'] = '';

        $padding = $bytes - strlen((string) json_encode($configuration));
        $this->assertGreaterThan(0, $padding, 'Requested size must exceed the fixture itself');

        $configuration['pad'] = str_repeat('a', $padding);
        $json = (string) json_encode($configuration);
        $this->assertSame($bytes, strlen($json), 'Padding must land on the requested size exactly');

        return $json;
    }

    private function loadMockFixture(string $filename): array
    {
        $path = __DIR__.'/../MockData/'.$filename;
        $contents = file_get_contents($path);
        $this->assertNotFalse($contents, sprintf('Mock fixture not readable: %s', $path));
        $decoded = json_decode($contents, true);
        $this->assertIsArray($decoded, sprintf('Mock fixture is not valid JSON: %s', $path));

        return $decoded;
    }

    /**
     * Build a provider whose discovery document is the standard fixture with
     * the given keys replaced. Used by the endpoint scheme tests to feed
     * deliberately-insecure endpoint URLs through `getSecureEndpoint`.
     *
     * The configuration is served from a cache hit, so no HTTP stub is needed
     * for the metadata document itself; the JWKS fixture answers the one fetch
     * that can still happen.
     *
     * @param array<string, string> $overrides Discovery document keys to replace
     */
    private function createProviderWithConfigurationOverrides(array $overrides, bool $allowHttp = false, string $clientId = self::CLIENT_ID): OpenIdConfigurationProvider
    {
        $configuration = array_merge($this->loadMockFixture('mockOpenIDConfiguration.json'), $overrides);

        $configCacheItem = $this->createStub(CacheItemInterface::class);
        $configCacheItem->method('isHit')->willReturn(true);
        $configCacheItem->method('get')->willReturn($configuration);

        $jwksCacheItem = $this->createStub(CacheItemInterface::class);
        $jwksCacheItem->method('isHit')->willReturn(false);

        $mockCacheItemPool = $this->createStub(CacheItemPoolInterface::class);
        $mockCacheItemPool->method('getItem')->willReturnCallback(
            fn (string $key) => str_contains($key, 'jwks') ? $jwksCacheItem : $configCacheItem
        );

        $mockHttpClient = $this->createStub(ClientInterface::class);
        $mockHttpClient->method('request')->willReturn(
            $this->getMockHttpSuccessResponse('/../MockData/mockOpenIDValidationKeys.json')
        );

        return new OpenIdConfigurationProvider([
            'openIDConnectMetadataUrl' => 'https://provider.example.org/openid-configuration',
            'cacheItemPool' => $mockCacheItemPool,
            'clientId' => $clientId,
            'clientSecret' => self::CLIENT_SECRET,
            'redirectUri' => self::REDIRECT_URI,
            'allowHttp' => $allowHttp,
        ], [
            'httpClient' => $mockHttpClient,
        ]);
    }

    /**
     * Build a provider whose JWKS endpoint returns the given raw JSON body.
     * Used by the JWKS validation tests to feed deliberately-malformed
     * payloads through `getJwtVerificationKeys`.
     */
    private function createProviderWithCustomJwks(string $jwksJson): OpenIdConfigurationProvider
    {
        $openIDConnectMetadataUrl = 'https://provider.example.org/openid-configuration';
        $jwks_uri = 'https://azure_b2c_test.b2clogin.com/azure_b2c_test.onmicrosoft.com/discovery/v2.0/keys?p=test-policy';

        $mockConfigResponse = $this->getMockHttpSuccessResponse('/../MockData/mockOpenIDConfiguration.json');

        $mockKeysStream = $this->createStub(StreamInterface::class);
        $mockKeysStream->method('getContents')->willReturn($jwksJson);
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

        return new OpenIdConfigurationProvider([
            'openIDConnectMetadataUrl' => $openIDConnectMetadataUrl,
            'cacheItemPool' => $mockCacheItemPool,
            'clientId' => self::CLIENT_ID,
            'clientSecret' => self::CLIENT_SECRET,
            'redirectUri' => self::REDIRECT_URI,
        ], [
            'httpClient' => $mockHttpClient,
        ]);
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
        // REQUIRED by OIDC Core §2 and asserted by validateIdToken(). The values
        // are never compared — firebase/php-jwt does that during the decode,
        // which is mocked out here — only their presence.
        $mockClaims->exp = 2000000000;
        $mockClaims->iat = 1000000000;

        return $mockClaims;
    }
}
