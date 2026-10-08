<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Tests\Unit\Configuration;

use PHPUnit\Framework\Attributes\Test;
use TYPO3\TestingFramework\Core\Unit\UnitTestCase;
use WapplerSystems\OidcConnect\Configuration\SecretResolver;

final class SecretResolverTest extends UnitTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        putenv('TEST_SECRET');
        putenv('OIDC_CONNECT_MAIN_CLIENT_SECRET');
        unset(
            $_ENV['TEST_SECRET'],
            $_SERVER['TEST_SECRET'],
            $_ENV['OIDC_CONNECT_MAIN_CLIENT_SECRET'],
            $_SERVER['OIDC_CONNECT_MAIN_CLIENT_SECRET']
        );
        unset($GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['oidc_connect']['clientSecrets']['main']);
    }

    protected function tearDown(): void
    {
        putenv('TEST_SECRET');
        putenv('OIDC_CONNECT_MAIN_CLIENT_SECRET');
        unset(
            $_ENV['TEST_SECRET'],
            $_SERVER['TEST_SECRET'],
            $_ENV['OIDC_CONNECT_MAIN_CLIENT_SECRET'],
            $_SERVER['OIDC_CONNECT_MAIN_CLIENT_SECRET']
        );
        unset($GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['oidc_connect']['clientSecrets']['main']);

        parent::tearDown();
    }

    #[Test]
    public function conventionalEnvNameAndResolveUseEnvironmentAndFallback(): void
    {
        self::assertSame('OIDC_CONNECT_MAIN_CLIENT_SECRET', SecretResolver::conventionalEnvName('main'));
        self::assertSame('OIDC_CONNECT_MY_SITE_DE_CLIENT_SECRET', SecretResolver::conventionalEnvName('my-site.de'));

        putenv('TEST_SECRET=from-env');
        $resolver = new SecretResolver();
        self::assertSame('from-env', $resolver->resolve('main', 'TEST_SECRET'));

        putenv('TEST_SECRET');
        $GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['oidc_connect']['clientSecrets']['main'] = 'from-config';
        self::assertSame('from-config', $resolver->resolve('main', ''));
    }
}
