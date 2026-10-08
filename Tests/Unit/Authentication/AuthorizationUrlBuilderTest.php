<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Tests\Unit\Authentication;

use PHPUnit\Framework\Attributes\Test;
use TYPO3\TestingFramework\Core\Unit\UnitTestCase;
use WapplerSystems\OidcConnect\Authentication\AuthorizationUrlBuilder;
use WapplerSystems\OidcConnect\Configuration\OidcConnectSettings;
use WapplerSystems\OidcConnect\Discovery\ProviderMetadata;

final class AuthorizationUrlBuilderTest extends UnitTestCase
{
    private OidcConnectSettings $settings;
    private ProviderMetadata $metadata;
    private AuthorizationUrlBuilder $builder;

    protected function setUp(): void
    {
        parent::setUp();

        $this->settings = new OidcConnectSettings('main', [
            'clientId' => 'typo3',
            'issuer' => 'https://idp.example/realms/r',
            'auth' => ['languageParameter' => 'ui_locales,kc_locale'],
        ]);

        $this->metadata = new ProviderMetadata(
            issuer: 'https://idp.example/realms/r',
            authorizationEndpoint: 'https://idp.example/auth',
            tokenEndpoint: 'https://idp.example/token',
            userinfoEndpoint: 'https://idp.example/userinfo',
            endSessionEndpoint: 'https://idp.example/end_session',
            jwksUri: 'https://idp.example/jwks',
            issParameterSupported: true,
            tokenEndpointAuthMethods: ['client_secret_basic'],
            signingAlgorithms: ['RS256'],
        );

        $this->builder = new AuthorizationUrlBuilder();
    }

    #[Test]
    public function buildCreatesUrlWithExpectedParametersAndStateRecord(): void
    {
        $result = $this->builder->build(
            $this->settings,
            $this->metadata,
            'https://www.example.com/oauth_callback',
            'FE',
            'https://www.example.com/after-login',
            'browser-binding-value',
        );

        $params = $this->queryParams($result['url']);

        self::assertSame('code', $params['response_type']);
        self::assertSame('typo3', $params['client_id']);
        self::assertSame('https://www.example.com/oauth_callback', $params['redirect_uri']);
        self::assertSame('openid', $params['scope']);
        self::assertNotEmpty($params['state']);
        self::assertNotEmpty($params['nonce']);
        self::assertSame('S256', $params['code_challenge_method']);

        $expectedChallenge = rtrim(strtr(
            base64_encode(hash('sha256', $result['record']->codeVerifier, true)),
            '+/',
            '-_'
        ), '=');
        self::assertSame($expectedChallenge, $params['code_challenge']);

        self::assertSame('FE', $result['record']->loginType);
        self::assertSame('https://www.example.com/after-login', $result['record']->returnUrl);
        self::assertSame('main', $result['record']->siteIdentifier);
        self::assertTrue($result['record']->matchesBrowser('browser-binding-value'));
        self::assertFalse($result['record']->matchesBrowser('other-binding-value'));
    }

    #[Test]
    public function silentAndLanguageParametersAreAdded(): void
    {
        $result = $this->builder->build(
            $this->settings,
            $this->metadata,
            'https://www.example.com/oauth_callback',
            'FE',
            'https://www.example.com/after-login',
            'browser-binding-value',
            'de',
            true,
        );

        $params = $this->queryParams($result['url']);

        self::assertSame('none', $params['prompt']);
        self::assertSame('de', $params['ui_locales']);
        self::assertSame('de', $params['kc_locale']);
    }

    private function queryParams(string $url): array
    {
        parse_str((string)parse_url($url, PHP_URL_QUERY), $params);
        return $params;
    }
}
