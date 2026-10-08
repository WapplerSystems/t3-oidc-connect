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
