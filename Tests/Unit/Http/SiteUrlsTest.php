<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Tests\Unit\Http;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Http\ServerRequest;
use TYPO3\TestingFramework\Core\Unit\UnitTestCase;
use WapplerSystems\OidcConnect\Http\SiteUrls;

final class SiteUrlsTest extends UnitTestCase
{
    public static function safeReturnUrlProvider(): array
    {
        return [
            'root-relative path is kept' => ['/foo?x=1', '/foo?x=1'],
            'protocol-relative URL is rejected' => ['//evil.example/x', ''],
            'other host is rejected' => ['https://evil.example/', ''],
            'same host absolute URL is kept' => ['https://www.example.com/a', 'https://www.example.com/a'],
            'javascript scheme is rejected' => ['javascript:alert(1)', ''],
            'backslash is rejected' => ['/\\evil', ''],
            'control characters are rejected' => ["/a\nb", ''],
        ];
    }

    #[Test]
    #[DataProvider('safeReturnUrlProvider')]
    public function safeReturnUrlOnlyAllowsLocalRootRelativeOrSameHost(string $candidate, string $expected): void
    {
        $request = new ServerRequest('https://www.example.com/page');

        self::assertSame($expected, SiteUrls::safeReturnUrl($candidate, $request));
    }

    public static function requestedReturnUrlProvider(): array
    {
        $loginPage = 'https://www.example.com/de/login/?redirect_url=' . rawurlencode('https://www.example.com/de/services/installation-center/');
        return [
            'redirect parameter' => ['/oidc/authorize?redirect=%2Fa%2F', '', '/a/'],
            'redirect_url parameter (felogin, causal/oidc)' => ['/oidc/authorize?redirect_url=%2Fb%2F', '', '/b/'],
            'redirect wins over redirect_url' => ['/oidc/authorize?redirect=%2Fa%2F&redirect_url=%2Fb%2F', '', '/a/'],
            'foreign redirect falls back to Referer' => ['/oidc/authorize?redirect=https%3A%2F%2Fevil.example%2F', 'https://www.example.com/c/', 'https://www.example.com/c/'],
            'plain Referer' => ['/oidc/authorize', 'https://www.example.com/c/', 'https://www.example.com/c/'],
            'login page as Referer is unwrapped' => ['/oidc/authorize', $loginPage, 'https://www.example.com/de/services/installation-center/'],
            'login page with foreign target stays on the Referer' => ['/oidc/authorize', 'https://www.example.com/de/login/?redirect_url=https%3A%2F%2Fevil.example%2F', 'https://www.example.com/de/login/?redirect_url=https%3A%2F%2Fevil.example%2F'],
            'foreign Referer is ignored' => ['/oidc/authorize', 'https://evil.example/?redirect=%2Fx%2F', ''],
            'nothing given' => ['/oidc/authorize', '', ''],
        ];
    }

    #[Test]
    #[DataProvider('requestedReturnUrlProvider')]
    public function requestedReturnUrlReadsQueryThenUnwrapsReferer(string $path, string $referer, string $expected): void
    {
        $uri = 'https://www.example.com' . $path;
        $query = [];
        parse_str((string)parse_url($uri, PHP_URL_QUERY), $query);
        $request = (new ServerRequest($uri))->withQueryParams($query);
        if ($referer !== '') {
            $request = $request->withHeader('Referer', $referer);
        }

        self::assertSame($expected, SiteUrls::requestedReturnUrl($request));
    }

    #[Test]
    public function matchesRouteMatchesPathUnderLanguageBaseButNotPartialSegments(): void
    {
        self::assertTrue(SiteUrls::matchesRoute(
            new ServerRequest('https://www.example.com/oauth_callback'),
            '/oauth_callback'
        ));
        self::assertTrue(SiteUrls::matchesRoute(
            new ServerRequest('https://www.example.com/en/oauth_callback'),
            '/oauth_callback'
        ));
        self::assertFalse(SiteUrls::matchesRoute(
            new ServerRequest('https://www.example.com/my-oauth_callback'),
            '/oauth_callback'
        ));
        self::assertFalse(SiteUrls::matchesRoute(
            new ServerRequest('https://www.example.com/oauth_callback'),
            ''
        ));
    }
}
