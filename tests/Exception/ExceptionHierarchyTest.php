<?php

namespace ItkDev\OpenIdConnect\Tests\Exception;

use ItkDev\OpenIdConnect\Exception\BadUrlException;
use ItkDev\OpenIdConnect\Exception\CacheException;
use ItkDev\OpenIdConnect\Exception\ClaimsException;
use ItkDev\OpenIdConnect\Exception\CodeException;
use ItkDev\OpenIdConnect\Exception\ConfigurationException;
use ItkDev\OpenIdConnect\Exception\DecodeException;
use ItkDev\OpenIdConnect\Exception\HttpException;
use ItkDev\OpenIdConnect\Exception\IllegalSchemeException;
use ItkDev\OpenIdConnect\Exception\JsonException;
use ItkDev\OpenIdConnect\Exception\JwksException;
use ItkDev\OpenIdConnect\Exception\MetadataException;
use ItkDev\OpenIdConnect\Exception\MissingParameterException;
use ItkDev\OpenIdConnect\Exception\NegativeCacheDurationException;
use ItkDev\OpenIdConnect\Exception\NegativeLeewayException;
use ItkDev\OpenIdConnect\Exception\OpenIdConnectExceptionInterface;
use ItkDev\OpenIdConnect\Exception\ValidationException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientExceptionInterface;

/**
 * Locks the exception contract documented in the "Exception handling"
 * section of `README.md`:
 *
 * - Every concrete exception thrown from a public method implements
 *   {@see OpenIdConnectExceptionInterface}.
 * - Each concrete extends the SPL type that best describes its failure
 *   category (`\RuntimeException`, `\LogicException`, or
 *   `\InvalidArgumentException`).
 * - A single `catch (OpenIdConnectExceptionInterface $e)` matches every
 *   concrete in the hierarchy.
 *
 * A change that breaks any of these properties is a MAJOR version bump
 * per SemVer commitments — failing this test class is the early warning.
 */
class ExceptionHierarchyTest extends TestCase
{
    /**
     * @return iterable<string, array{class-string<\Throwable>, class-string<\Throwable>}>
     */
    public static function concreteProvider(): iterable
    {
        // Programmer / config errors → \LogicException
        yield 'BadUrlException' => [BadUrlException::class, \LogicException::class];
        yield 'IllegalSchemeException' => [IllegalSchemeException::class, \LogicException::class];
        yield 'MissingParameterException' => [MissingParameterException::class, \LogicException::class];

        // Invalid input to a public method / constructor → \InvalidArgumentException
        yield 'ConfigurationException' => [ConfigurationException::class, \InvalidArgumentException::class];
        yield 'NegativeCacheDurationException' => [NegativeCacheDurationException::class, \InvalidArgumentException::class];
        yield 'NegativeLeewayException' => [NegativeLeewayException::class, \InvalidArgumentException::class];

        // Runtime conditions → \RuntimeException
        yield 'CacheException' => [CacheException::class, \RuntimeException::class];
        yield 'HttpException' => [HttpException::class, \RuntimeException::class];
        yield 'JsonException' => [JsonException::class, \RuntimeException::class];
        yield 'DecodeException' => [DecodeException::class, \RuntimeException::class];
        yield 'JwksException' => [JwksException::class, \RuntimeException::class];
        yield 'CodeException' => [CodeException::class, \RuntimeException::class];
        yield 'ValidationException' => [ValidationException::class, \RuntimeException::class];
        yield 'ClaimsException' => [ClaimsException::class, \RuntimeException::class];
        yield 'MetadataException' => [MetadataException::class, \RuntimeException::class];
    }

    /**
     * @param class-string<\Throwable> $concrete
     * @param class-string<\Throwable> $expectedSplParent
     */
    #[DataProvider('concreteProvider')]
    public function testConcreteImplementsMarker(string $concrete, string $expectedSplParent): void
    {
        $instance = new $concrete('test');
        $this->assertInstanceOf(OpenIdConnectExceptionInterface::class, $instance);
        $this->assertInstanceOf(\Throwable::class, $instance);
    }

    /**
     * @param class-string<\Throwable> $concrete
     * @param class-string<\Throwable> $expectedSplParent
     */
    #[DataProvider('concreteProvider')]
    public function testConcreteExtendsExpectedSplParent(string $concrete, string $expectedSplParent): void
    {
        $instance = new $concrete('test');
        $this->assertInstanceOf($expectedSplParent, $instance);
    }

    /**
     * @param class-string<\Throwable> $concrete
     * @param class-string<\Throwable> $expectedSplParent
     */
    #[DataProvider('concreteProvider')]
    public function testCatchByMarkerMatchesEveryConcrete(string $concrete, string $expectedSplParent): void
    {
        try {
            throw new $concrete('test');
        } catch (OpenIdConnectExceptionInterface $caught) {
            $this->assertInstanceOf($concrete, $caught);

            return;
        }
        // @phpstan-ignore deadCode.unreachable (safety net if a future regression breaks the catch-by-marker contract)
        $this->fail('Catch on OpenIdConnectExceptionInterface should have matched '.$concrete);
    }

    public function testHttpExceptionAlsoImplementsPsr18ClientInterface(): void
    {
        // HttpException is part of the public contract for two markers — the
        // OIDC marker and PSR-18's ClientExceptionInterface — so a PSR-18-savvy
        // consumer can catch HTTP failures via the standard PSR interface.
        $instance = new HttpException('test');
        $this->assertInstanceOf(ClientExceptionInterface::class, $instance);
    }

    public function testAbstractBaseImplementsMarker(): void
    {
        // The deprecated abstract `ItkOpenIdConnectException` is kept for
        // backward compatibility through 5.x and still implements the marker.
        // Catch sites that wrote `catch (ItkOpenIdConnectException $e)` should
        // migrate to the marker interface; this assertion guards the marker
        // implementation while the deprecation window is open.
        //
        // ReflectionClass keeps the check at runtime so PHPStan can't fold it
        // into a constant tautology — the value of the test is catching a
        // *future* regression that removes the marker from the abstract.
        $reflection = new \ReflectionClass(\ItkDev\OpenIdConnect\Exception\ItkOpenIdConnectException::class);
        $this->assertContains(
            OpenIdConnectExceptionInterface::class,
            $reflection->getInterfaceNames(),
            'Deprecated abstract must still implement the marker for 5.x BC.',
        );
    }
}
