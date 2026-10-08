<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Tests\Unit\Token;

use Firebase\JWT\JWT;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Cache\Backend\TransientMemoryBackend;
use TYPO3\CMS\Core\Cache\Frontend\VariableFrontend;
use TYPO3\CMS\Core\Http\RequestFactory;
use TYPO3\CMS\Core\Http\Response;
use TYPO3\TestingFramework\Core\Unit\UnitTestCase;
use WapplerSystems\OidcConnect\Configuration\OidcConnectSettings;
use WapplerSystems\OidcConnect\Discovery\ProviderMetadata;
use WapplerSystems\OidcConnect\Token\IdTokenValidator;
use WapplerSystems\OidcConnect\Token\JwksProvider;
use WapplerSystems\OidcConnect\Token\TokenValidationException;

final class IdTokenValidatorTest extends UnitTestCase
{
    protected bool $resetSingletonInstances = true;

    private const NONCE = 'expected-nonce';

    private string $privateKeyPem;
    private array $jwk;
    private OidcConnectSettings $settings;
    private ProviderMetadata $metadata;
    private VariableFrontend $cache;

    protected function setUp(): void
    {
        parent::setUp();
        JWT::$leeway = 0;

        $this->privateKeyPem = $this->generatePrivateKey();
        $this->jwk = $this->buildJwk($this->privateKeyPem);
        $this->settings = $this->createSettings();
        $this->metadata = $this->createMetadata();
        $this->cache = new VariableFrontend('test', new TransientMemoryBackend());
    }

    protected function tearDown(): void
    {
        JWT::$leeway = 0;
        parent::tearDown();
    }

    #[Test]
    public function validIdTokenReturnsClaims(): void
    {
        $token = $this->sign($this->baseClaims());

        $claims = $this->validator()->validateIdToken($token, $this->settings, $this->metadata, self::NONCE);

        self::assertSame('typo3', $claims['aud']);
        self::assertSame(self::NONCE, $claims['nonce']);
        self::assertSame('user123', $claims['sub']);
    }

    #[Test]
    public function wrongIssuerIsRejected(): void
    {
        $claims = $this->baseClaims();
        $claims['iss'] = 'https://evil.example';
        $token = $this->sign($claims);

        $this->expectException(TokenValidationException::class);
        $this->validator()->validateIdToken($token, $this->settings, $this->metadata, self::NONCE);
    }

    #[Test]
    public function tokenAudienceWithoutClientIdIsRejected(): void
    {
        $claims = $this->baseClaims();
        $claims['aud'] = 'other-client';
        $token = $this->sign($claims);

        $this->expectException(TokenValidationException::class);
        $this->validator()->validateIdToken($token, $this->settings, $this->metadata, self::NONCE);
    }

    #[Test]
    public function multipleAudienceTokenRequiresMatchingAzp(): void
    {
        $claims = $this->baseClaims();
        $claims['aud'] = ['typo3', 'other-client'];
        $token = $this->sign($claims);

        try {
            $this->validator()->validateIdToken($token, $this->settings, $this->metadata, self::NONCE);
            $this->fail('Expected TokenValidationException for missing azp');
        } catch (TokenValidationException $e) {
            self::assertSame(1747600042, $e->getCode());
        }

        $claims['azp'] = 'typo3';
        $token = $this->sign($claims);

        $result = $this->validator()->validateIdToken($token, $this->settings, $this->metadata, self::NONCE);

        self::assertSame('typo3', $result['azp']);
    }

    #[Test]
    public function azpDifferentFromClientIsRejected(): void
    {
        $claims = $this->baseClaims();
        $claims['aud'] = 'typo3';
        $claims['azp'] = 'other-client';
        $token = $this->sign($claims);

        $this->expectException(TokenValidationException::class);
        $this->validator()->validateIdToken($token, $this->settings, $this->metadata, self::NONCE);
    }

    #[Test]
    public function nonceMismatchAndEmptyExpectedNonceAreRejected(): void
    {
        $token = $this->sign($this->baseClaims());

        try {
            $this->validator()->validateIdToken($token, $this->settings, $this->metadata, 'wrong-nonce');
            $this->fail('Expected TokenValidationException for nonce mismatch');
        } catch (TokenValidationException $e) {
            self::assertSame(1747600023, $e->getCode());
        }

        try {
            $this->validator()->validateIdToken($token, $this->settings, $this->metadata, '');
            $this->fail('Expected TokenValidationException for empty expected nonce');
        } catch (TokenValidationException $e) {
            self::assertSame(1747600023, $e->getCode());
        }
    }

    #[Test]
    public function expiredTokenIsRejected(): void
    {
        $claims = $this->baseClaims();
        $claims['exp'] = time() - 3600;
        $token = $this->sign($claims);

        $this->expectException(TokenValidationException::class);
        $this->validator()->validateIdToken($token, $this->settings, $this->metadata, self::NONCE);
    }

    #[Test]
    public function tokenSignedByDifferentKeyWithSameKidIsRejected(): void
    {
        $otherKeyPem = $this->generatePrivateKey();
        $token = $this->sign($this->baseClaims(), $otherKeyPem);

        $this->expectException(TokenValidationException::class);
        $this->validator()->validateIdToken($token, $this->settings, $this->metadata, self::NONCE);
    }

    #[Test]
    public function tokenWithDisallowedAlgorithmIsRejected(): void
    {
        $token = $this->sign($this->baseClaims(), str_repeat('s', 64), 'HS256');

        $this->expectException(TokenValidationException::class);
        $this->validator()->validateIdToken($token, $this->settings, $this->metadata, self::NONCE);
    }

    #[Test]
    public function atHashMismatchIsRejectedAndCorrectAtHashIsAccepted(): void
    {
        $accessToken = 'access-token-value';

        $claims = $this->baseClaims();
        $claims['at_hash'] = 'wrong-at-hash';
        $token = $this->sign($claims);

        try {
            $this->validator()->validateIdToken($token, $this->settings, $this->metadata, self::NONCE, $accessToken);
            $this->fail('Expected TokenValidationException for at_hash mismatch');
        } catch (TokenValidationException $e) {
            self::assertSame(1747600024, $e->getCode());
        }

        $hash = hash('sha256', $accessToken, true);
        $correct = rtrim(strtr(base64_encode(substr($hash, 0, intdiv(strlen($hash), 2))), '+/', '-_'), '=');
        $claims['at_hash'] = $correct;
        $token = $this->sign($claims);

        $result = $this->validator()->validateIdToken($token, $this->settings, $this->metadata, self::NONCE, $accessToken);

        self::assertSame($correct, $result['at_hash']);
    }

    #[Test]
    public function validLogoutTokenIsAcceptedAndReplayIsRejected(): void
    {
        $token = $this->sign($this->logoutClaims());

        $result = $this->validator()->validateLogoutToken($token, $this->settings, $this->metadata);
        self::assertSame('unique-jti', $result['jti']);
        self::assertSame('session-123', $result['sid']);

        try {
            $this->validator()->validateLogoutToken($token, $this->settings, $this->metadata);
            $this->fail('Expected TokenValidationException for replay');
        } catch (TokenValidationException $e) {
            self::assertSame(1747600036, $e->getCode());
        }
    }

    #[Test]
    public function logoutTokenWithNonceOrMissingRequiredClaimsIsRejected(): void
    {
        $claims = $this->logoutClaims();
        $claims['nonce'] = 'unexpected-nonce';
        $token = $this->sign($claims);

        try {
            $this->validator()->validateLogoutToken($token, $this->settings, $this->metadata);
            $this->fail('Expected rejection of logout token with nonce');
        } catch (TokenValidationException $e) {
            self::assertSame(1747600033, $e->getCode());
        }

        $claims = $this->logoutClaims();
        unset($claims['events']);
        $token = $this->sign($claims);

        try {
            $this->validator()->validateLogoutToken($token, $this->settings, $this->metadata);
            $this->fail('Expected rejection of logout token without events');
        } catch (TokenValidationException $e) {
            self::assertSame(1747600032, $e->getCode());
        }

        $claims = $this->logoutClaims();
        unset($claims['sid']);
        $token = $this->sign($claims);

        try {
            $this->validator()->validateLogoutToken($token, $this->settings, $this->metadata);
            $this->fail('Expected rejection of logout token without sid or sub');
        } catch (TokenValidationException $e) {
            self::assertSame(1747600034, $e->getCode());
        }
    }

    private function validator(): IdTokenValidator
    {
        $requestFactory = $this->createStub(RequestFactory::class);
        $requestFactory->method('request')->willReturnCallback(
            fn($url, $method, $options) => $this->responseWithJson(['keys' => [$this->jwk]])
        );

        return new IdTokenValidator(
            new JwksProvider($requestFactory, $this->cache),
            $this->cache
        );
    }

    private function responseWithJson(array $data): Response
    {
        $response = new Response();
        $response->getBody()->write((string)json_encode($data));
        $response->getBody()->rewind();
        return $response;
    }

    private function baseClaims(): array
    {
        return [
            'iss' => 'https://idp.example/realms/r',
            'aud' => 'typo3',
            'nonce' => self::NONCE,
            'exp' => time() + 3600,
            'iat' => time(),
            'sub' => 'user123',
        ];
    }

    private function logoutClaims(): array
    {
        return [
            'iss' => 'https://idp.example/realms/r',
            'aud' => 'typo3',
            'iat' => time(),
            'jti' => 'unique-jti',
            'events' => [
                IdTokenValidator::BACKCHANNEL_LOGOUT_EVENT => (object)[],
            ],
            'sid' => 'session-123',
        ];
    }

    private function sign(array $claims, ?string $key = null, string $alg = 'RS256', string $kid = 'k1'): string
    {
        $key ??= $this->privateKeyPem;
        return JWT::encode($claims, $key, $alg, $kid);
    }

    private function createSettings(): OidcConnectSettings
    {
        return new OidcConnectSettings('main', [
            'clientId' => 'typo3',
            'issuer' => 'https://idp.example/realms/r',
            'auth' => ['clockSkew' => 60],
        ]);
    }

    private function createMetadata(): ProviderMetadata
    {
        return new ProviderMetadata(
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
    }

    private function generatePrivateKey(): string
    {
        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        if ($key === false) {
            throw new \RuntimeException('Unable to create private key');
        }
        openssl_pkey_export($key, $pem);
        return $pem;
    }

    private function buildJwk(string $privateKeyPem): array
    {
        $key = openssl_pkey_get_private($privateKeyPem);
        $details = openssl_pkey_get_details($key);
        return [
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'kid' => 'k1',
            'n' => self::base64url($details['rsa']['n']),
            'e' => self::base64url($details['rsa']['e']),
        ];
    }

    private static function base64url(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }
}
