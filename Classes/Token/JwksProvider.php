<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Token;

use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use TYPO3\CMS\Core\Cache\Frontend\FrontendInterface;
use TYPO3\CMS\Core\Http\RequestFactory;

/**
 * Fetches and caches the provider's JSON Web Key Set.
 *
 * Key rotation: when a token references an unknown `kid`, the set is
 * refetched once; refetches are rate-limited so a flood of forged tokens
 * with random `kid`s cannot turn TYPO3 into a JWKS hammer.
 */
final class JwksProvider implements LoggerAwareInterface
{
    use LoggerAwareTrait;

    private const CACHE_TTL = 86400;
    private const REFETCH_INTERVAL = 300;

    public function __construct(
        private readonly RequestFactory $requestFactory,
        #[Autowire(service: 'cache.oidc_connect')]
        private readonly FrontendInterface $cache,
    ) {}

    /**
     * @param list<string> $allowedAlgorithms
     * @return array<string, Key> keyed by kid
     * @throws TokenValidationException
     */
    public function keysFor(string $jwksUri, ?string $kid, array $allowedAlgorithms): array
    {
        if ($jwksUri === '') {
            throw new TokenValidationException('No jwks_uri known for this provider.', 1747600001);
        }
        $cacheKey = 'jwks_' . hash('sha256', $jwksUri);
        $jwks = $this->cache->get($cacheKey);
        if (!is_array($jwks)) {
            $jwks = $this->fetch($jwksUri, $cacheKey);
        }
        $keys = $this->parse($jwks, $allowedAlgorithms);

        if ($kid !== null && !isset($keys[$kid])) {
            $lockKey = $cacheKey . '_refetched';
            if (!$this->cache->has($lockKey)) {
                $this->cache->set($lockKey, true, [], self::REFETCH_INTERVAL);
                $this->logger?->info('oidc-connect: unknown kid {kid}, refetching JWKS', ['kid' => $kid]);
                $keys = $this->parse($this->fetch($jwksUri, $cacheKey), $allowedAlgorithms);
            }
        }
        return $keys;
    }

    /** @return array<string, mixed> */
    private function fetch(string $jwksUri, string $cacheKey): array
    {
        try {
            $response = $this->requestFactory->request($jwksUri, 'GET', [
                'headers' => ['Accept' => 'application/json'],
                'timeout' => 10,
                'http_errors' => false,
            ]);
            $jwks = json_decode((string)$response->getBody(), true, 32, JSON_THROW_ON_ERROR);
        } catch (\Throwable $e) {
            throw new TokenValidationException('Could not load JWKS: ' . $e->getMessage(), 1747600002, $e);
        }
        if ($response->getStatusCode() !== 200 || !is_array($jwks) || !is_array($jwks['keys'] ?? null)) {
            throw new TokenValidationException('JWKS endpoint returned no key set.', 1747600003);
        }
        $this->cache->set($cacheKey, $jwks, ['oidc_connect_jwks'], self::CACHE_TTL);
        return $jwks;
    }

    /**
     * @param array<string, mixed> $jwks
     * @param list<string> $allowedAlgorithms
     * @return array<string, Key>
     */
    private function parse(array $jwks, array $allowedAlgorithms): array
    {
        $signingKeys = [];
        foreach ((array)($jwks['keys'] ?? []) as $index => $jwk) {
            if (!is_array($jwk) || ($jwk['use'] ?? 'sig') !== 'sig') {
                continue; // Keycloak also publishes RSA-OAEP encryption keys
            }
            if (isset($jwk['alg']) && !in_array($jwk['alg'], $allowedAlgorithms, true)) {
                continue;
            }
            $jwk['kid'] ??= 'idx' . $index;
            $signingKeys[] = $jwk;
        }
        if ($signingKeys === []) {
            return [];
        }
        try {
            // Keys without "alg" (allowed by RFC 7517) fall back to RS256.
            return JWK::parseKeySet(['keys' => $signingKeys], 'RS256');
        } catch (\Throwable $e) {
            throw new TokenValidationException('JWKS could not be parsed: ' . $e->getMessage(), 1747600004, $e);
        }
    }
}
