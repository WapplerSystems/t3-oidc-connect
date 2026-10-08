<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Token;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use TYPO3\CMS\Core\Cache\Frontend\FrontendInterface;
use WapplerSystems\OidcConnect\Configuration\OidcConnectSettings;
use WapplerSystems\OidcConnect\Discovery\ProviderMetadata;

/**
 * Validates ID tokens (OIDC Core §3.1.3.7) and back-channel logout tokens
 * (OIDC Back-Channel Logout §2.6).
 *
 * Signature, `exp`, `nbf` and `iat` are verified by firebase/php-jwt; the
 * OIDC-specific claims (`iss`, `aud`, `azp`, `nonce`, `at_hash`, `events`,
 * `jti`) are verified here.
 */
final class IdTokenValidator
{
    public const BACKCHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    public function __construct(
        private readonly JwksProvider $jwksProvider,
        #[Autowire(service: 'cache.oidc_connect')]
        private readonly FrontendInterface $cache,
    ) {}

    /**
     * @return array<string, mixed> the verified claims
     * @throws TokenValidationException
     */
    public function validateIdToken(
        string $idToken,
        OidcConnectSettings $settings,
        ProviderMetadata $metadata,
        string $expectedNonce,
        ?string $accessToken = null,
    ): array {
        [$header, $claims] = $this->verifySignature($idToken, $settings, $metadata);

        $this->assertIssuerAndAudience($claims, $settings, $metadata);

        if (!isset($claims['iat']) || !is_numeric($claims['iat'])) {
            throw new TokenValidationException('ID token has no iat claim.', 1747600020);
        }
        if (!isset($claims['exp'])) {
            throw new TokenValidationException('ID token has no exp claim.', 1747600021);
        }
        if (!is_string($claims['sub'] ?? null) || $claims['sub'] === '') {
            throw new TokenValidationException('ID token has no sub claim.', 1747600022);
        }
        if ($expectedNonce === '' || !is_string($claims['nonce'] ?? null) || !hash_equals($expectedNonce, $claims['nonce'])) {
            throw new TokenValidationException('ID token nonce does not match.', 1747600023);
        }
        if ($accessToken !== null && isset($claims['at_hash'])) {
            $expected = $this->halfHash($accessToken, (string)$header['alg']);
            if ($expected !== null && !hash_equals($expected, (string)$claims['at_hash'])) {
                throw new TokenValidationException('ID token at_hash does not match the access token.', 1747600024);
            }
        }
        return $claims;
    }

    /**
     * @return array<string, mixed> the verified claims
     * @throws TokenValidationException
     */
    public function validateLogoutToken(string $logoutToken, OidcConnectSettings $settings, ProviderMetadata $metadata): array
    {
        [, $claims] = $this->verifySignature($logoutToken, $settings, $metadata);

        $this->assertIssuerAndAudience($claims, $settings, $metadata);

        if (!isset($claims['iat']) || !is_numeric($claims['iat'])) {
            throw new TokenValidationException('Logout token has no iat claim.', 1747600030);
        }
        if (abs(time() - (int)$claims['iat']) > 600 + $settings->clockSkew()) {
            throw new TokenValidationException('Logout token is too old or from the future.', 1747600031);
        }
        $events = $claims['events'] ?? null;
        if (!is_array($events) || !array_key_exists(self::BACKCHANNEL_LOGOUT_EVENT, $events)) {
            throw new TokenValidationException('Logout token lacks the back-channel logout event.', 1747600032);
        }
        if (array_key_exists('nonce', $claims)) {
            throw new TokenValidationException('Logout token must not contain a nonce.', 1747600033);
        }
        if (empty($claims['sid']) && empty($claims['sub'])) {
            throw new TokenValidationException('Logout token has neither sid nor sub.', 1747600034);
        }
        $jti = (string)($claims['jti'] ?? '');
        if ($jti === '') {
            throw new TokenValidationException('Logout token has no jti claim.', 1747600035);
        }
        $replayKey = 'logout_jti_' . hash('sha256', $metadata->issuer . '|' . $jti);
        if ($this->cache->has($replayKey)) {
            throw new TokenValidationException('Logout token has already been used.', 1747600036);
        }
        $this->cache->set($replayKey, true, [], 1200);
        return $claims;
    }

    /**
     * @return array{0: array<string, mixed>, 1: array<string, mixed>}
     */
    private function verifySignature(string $jwt, OidcConnectSettings $settings, ProviderMetadata $metadata): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new TokenValidationException('Token is not a signed JWT.', 1747600010);
        }
        try {
            $header = json_decode(JWT::urlsafeB64Decode($parts[0]), true, 8, JSON_THROW_ON_ERROR);
        } catch (\Throwable $e) {
            throw new TokenValidationException('Token header is not valid JSON.', 1747600011, $e);
        }
        if (!is_array($header)) {
            throw new TokenValidationException('Token header is not valid JSON.', 1747600011);
        }
        $algorithm = (string)($header['alg'] ?? '');
        $allowed = $settings->allowedSigningAlgorithms();
        if ($metadata->signingAlgorithms !== []) {
            $allowed = array_values(array_intersect($allowed, $metadata->signingAlgorithms));
        }
        if (!in_array($algorithm, $allowed, true)) {
            throw new TokenValidationException(sprintf('Token algorithm "%s" is not allowed.', $algorithm), 1747600012);
        }

        $kid = isset($header['kid']) ? (string)$header['kid'] : null;
        $keys = $this->jwksProvider->keysFor($metadata->jwksUri, $kid, $allowed);
        if ($kid !== null) {
            if (!isset($keys[$kid])) {
                throw new TokenValidationException(sprintf('No signing key with kid "%s".', $kid), 1747600013);
            }
            $keyOrKeys = $keys[$kid];
        } elseif (count($keys) === 1) {
            $keyOrKeys = reset($keys);
        } else {
            throw new TokenValidationException('Token has no kid and the JWKS is ambiguous.', 1747600014);
        }
        if (!$keyOrKeys instanceof Key || $keyOrKeys->getAlgorithm() !== $algorithm) {
            throw new TokenValidationException('Signing key algorithm does not match the token.', 1747600015);
        }

        $previousLeeway = JWT::$leeway;
        JWT::$leeway = $settings->clockSkew();
        try {
            $payload = JWT::decode($jwt, $keyOrKeys);
        } catch (\Throwable $e) {
            throw new TokenValidationException('Token rejected: ' . $e->getMessage(), 1747600016, $e);
        } finally {
            JWT::$leeway = $previousLeeway;
        }
        $claims = json_decode((string)json_encode($payload), true);
        if (!is_array($claims)) {
            throw new TokenValidationException('Token payload is not an object.', 1747600017);
        }
        return [$header, $claims];
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function assertIssuerAndAudience(array $claims, OidcConnectSettings $settings, ProviderMetadata $metadata): void
    {
        if ($metadata->issuer === '' || rtrim((string)($claims['iss'] ?? ''), '/') !== rtrim($metadata->issuer, '/')) {
            throw new TokenValidationException('Token issuer does not match.', 1747600040);
        }
        $clientId = $settings->clientId();
        $audience = $claims['aud'] ?? [];
        $audience = is_array($audience) ? array_map('strval', $audience) : [(string)$audience];
        if (!in_array($clientId, $audience, true)) {
            throw new TokenValidationException('Token audience does not contain this client.', 1747600041);
        }
        $azp = isset($claims['azp']) ? (string)$claims['azp'] : null;
        if ((count($audience) > 1 && $azp === null) || ($azp !== null && $azp !== $clientId)) {
            throw new TokenValidationException('Token authorized party does not match this client.', 1747600042);
        }
    }

    /**
     * Left-most half of the hash of the access token (OIDC Core §3.1.3.6).
     */
    private function halfHash(string $value, string $algorithm): ?string
    {
        $bits = (int)substr($algorithm, 2);
        $hashAlgorithm = match ($bits) {
            256 => 'sha256',
            384 => 'sha384',
            512 => 'sha512',
            default => null,
        };
        if ($hashAlgorithm === null) {
            return null;
        }
        $hash = hash($hashAlgorithm, $value, true);
        return rtrim(strtr(base64_encode(substr($hash, 0, intdiv(strlen($hash), 2))), '+/', '-_'), '=');
    }
}
