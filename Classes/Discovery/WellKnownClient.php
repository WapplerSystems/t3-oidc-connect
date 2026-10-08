<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Discovery;

use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use TYPO3\CMS\Core\Cache\Frontend\FrontendInterface;
use TYPO3\CMS\Core\Http\RequestFactory;

/**
 * Loads + caches the OpenID Connect Discovery document for an issuer.
 *
 * The well-known location is `<issuer>/.well-known/openid-configuration`
 * (RFC 8414). Discovery documents are practically static — projects can
 * skip configuring individual endpoint URLs in `oidcConnect.endpoints.*`
 * and rely on auto-discovery. Endpoint overrides from the site settings
 * always win over the discovery document (see
 * {@see \WapplerSystems\OidcConnect\Configuration\OidcConnectSettings::endpoint()}).
 *
 * Errors during fetch (network, non-2xx, invalid JSON) bubble up as
 * {@see DiscoveryException} so callers can decide whether to fall back
 * to manual endpoints or surface the failure.
 */
final class WellKnownClient implements LoggerAwareInterface
{
    use LoggerAwareTrait;

    private const CACHE_TTL = 3600; // 1 h — discovery docs rarely change

    public function __construct(
        private readonly RequestFactory $requestFactory,
        #[Autowire(service: 'cache.oidc_connect')]
        private readonly FrontendInterface $cache,
    ) {}

    /**
     * Fetch the discovery document for the given issuer. Result is cached
     * by hash of the issuer URL.
     *
     * @throws DiscoveryException on network/parse failure
     */
    public function discover(string $issuer): OidcDiscoveryDocument
    {
        $issuer = rtrim($issuer, '/');
        if ($issuer === '') {
            throw new DiscoveryException('Empty issuer URL.');
        }

        $cacheKey = 'wellknown_' . hash('sha256', $issuer);
        $cached = $this->cache->get($cacheKey);
        if (is_array($cached)) {
            return new OidcDiscoveryDocument($cached);
        }

        $url = $issuer . '/.well-known/openid-configuration';
        try {
            $response = $this->requestFactory->request($url, 'GET', [
                'headers' => ['Accept' => 'application/json'],
                'timeout' => 10,
            ]);
        } catch (\Throwable $e) {
            $this->logger?->error('oidc-connect: discovery fetch failed for {issuer}: {error}', [
                'issuer' => $issuer,
                'error' => $e->getMessage(),
            ]);
            throw new DiscoveryException(
                sprintf('Could not fetch discovery document from %s: %s', $url, $e->getMessage()),
                1747400001,
                $e
            );
        }

        $status = $response->getStatusCode();
        if ($status < 200 || $status >= 300) {
            throw new DiscoveryException(
                sprintf('Discovery endpoint %s returned HTTP %d.', $url, $status),
                1747400002
            );
        }

        $body = (string)$response->getBody();
        try {
            $decoded = json_decode($body, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new DiscoveryException(
                sprintf('Discovery document at %s is not valid JSON: %s', $url, $e->getMessage()),
                1747400003,
                $e
            );
        }
        if (!is_array($decoded)) {
            throw new DiscoveryException(sprintf('Discovery document at %s is not a JSON object.', $url), 1747400004);
        }

        $this->cache->set($cacheKey, $decoded, [], self::CACHE_TTL);
        return new OidcDiscoveryDocument($decoded);
    }

    /**
     * Invalidate the cached discovery document for an issuer. Useful in
     * tests or when an admin rotates IdP endpoints.
     */
    public function forget(string $issuer): void
    {
        $issuer = rtrim($issuer, '/');
        if ($issuer !== '') {
            $this->cache->remove('wellknown_' . hash('sha256', $issuer));
        }
    }
}
