<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Authentication;

use Symfony\Component\DependencyInjection\Attribute\Autowire;
use TYPO3\CMS\Core\Cache\Frontend\FrontendInterface;

/**
 * Default state store on the `oidc_connect` cache. Entries are removed on
 * the first read, so a state can be consumed only once.
 */
final readonly class CacheBackedAuthorizationStateStore implements AuthorizationStateStoreInterface
{
    public function __construct(
        #[Autowire(service: 'cache.oidc_connect')]
        private FrontendInterface $cache,
    ) {}

    public function save(AuthorizationStateRecord $record, int $ttl = 600): void
    {
        if ($record->state === '') {
            throw new \LogicException('AuthorizationStateRecord::$state must not be empty.', 1747700001);
        }
        $this->cache->set($this->cacheKey($record->state), $record->toArray(), ['oidc_connect_state'], $ttl);
    }

    public function consume(string $state): ?AuthorizationStateRecord
    {
        if ($state === '' || preg_match('/^[A-Za-z0-9_-]{20,128}$/', $state) !== 1) {
            return null;
        }
        $key = $this->cacheKey($state);
        $data = $this->cache->get($key);
        if (!is_array($data)) {
            return null;
        }
        $this->cache->remove($key);
        return AuthorizationStateRecord::fromArray($data);
    }

    public function discard(string $state): void
    {
        if ($state !== '' && preg_match('/^[A-Za-z0-9_-]{20,128}$/', $state) === 1) {
            $this->cache->remove($this->cacheKey($state));
        }
    }

    private function cacheKey(string $state): string
    {
        return 'state_' . $state;
    }
}
