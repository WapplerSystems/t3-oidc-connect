<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Discovery;

use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use TYPO3\CMS\Core\Cache\Frontend\FrontendInterface;
use TYPO3\CMS\Core\Http\RequestFactory;

/**
 * Loads and caches the OpenID Connect discovery document of an issuer and
 * verifies that it really describes that issuer (OIDC Discovery §4.3).
 */
final class WellKnownClient implements LoggerAwareInterface
{
    use LoggerAwareTrait;

    private const CACHE_TTL = 86400;

    public function __construct(
        private readonly RequestFactory $requestFactory,
        #[Autowire(service: 'cache.oidc_connect')]
        private readonly FrontendInterface $cache,
    ) {}

    /**
     * @throws DiscoveryException
     */
    public function discover(string $issuer): OidcDiscoveryDocument
    {
        $issuer = rtrim($issuer, '/');
        if ($issuer === '') {
            throw new DiscoveryException('Empty issuer URL.', 1747400000);
        }

        $cacheKey = $this->cacheKey($issuer);
        $cached = $this->cache->get($cacheKey);
        if (is_array($cached)) {
            return new OidcDiscoveryDocument($cached);
        }

        $url = $issuer . '/.well-known/openid-configuration';
        try {
            $response = $this->requestFactory->request($url, 'GET', [
                'headers' => ['Accept' => 'application/json'],
                'timeout' => 10,
                'http_errors' => false,
            ]);
        } catch (\Throwable $e) {
            $this->logger?->error('oidc-connect: discovery fetch failed for {issuer}: {error}', [
                'issuer' => $issuer,
                'error' => $e->getMessage(),
            ]);
            throw new DiscoveryException(sprintf('Could not fetch %s: %s', $url, $e->getMessage()), 1747400001, $e);
        }

        $status = $response->getStatusCode();
        if ($status < 200 || $status >= 300) {
            throw new DiscoveryException(sprintf('Discovery endpoint %s returned HTTP %d.', $url, $status), 1747400002);
        }

        try {
            $decoded = json_decode((string)$response->getBody(), true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new DiscoveryException(sprintf('Discovery document at %s is not valid JSON: %s', $url, $e->getMessage()), 1747400003, $e);
        }
        if (!is_array($decoded)) {
            throw new DiscoveryException(sprintf('Discovery document at %s is not a JSON object.', $url), 1747400004);
        }

        $document = new OidcDiscoveryDocument($decoded);
        if (rtrim($document->issuer(), '/') !== $issuer) {
            throw new DiscoveryException(
                sprintf('Discovery document at %s announces issuer "%s", expected "%s".', $url, $document->issuer(), $issuer),
                1747400005
            );
        }

        $this->cache->set($cacheKey, $decoded, ['oidc_connect_discovery'], self::CACHE_TTL);
        return $document;
    }

    public function forget(string $issuer): void
    {
        $issuer = rtrim($issuer, '/');
        if ($issuer !== '') {
            $this->cache->remove($this->cacheKey($issuer));
        }
    }

    private function cacheKey(string $issuer): string
    {
        return 'wellknown_' . hash('sha256', $issuer);
    }
}
