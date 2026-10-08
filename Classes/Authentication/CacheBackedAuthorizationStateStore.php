<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Authentication;

use Symfony\Component\DependencyInjection\Attribute\Autowire;
use TYPO3\CMS\Core\Cache\Frontend\FrontendInterface;

/**
 * Default implementation backed by the dedicated `cache.oidc_connect`
 * cache frontend (configured in {@see ../../ext_localconf.php} and wired
 * to the DI container via Services.yaml).
 *
 * One-time consume is realised by removing the entry from the cache on
 * a successful read. Two simultaneous callback hits with the same state
 * — practically impossible in a normal Authorization Code Flow but
 * conceivable on retries — will resolve to exactly one record returned
 * and one null; both outcomes are explicitly handled by the caller.
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
            throw new \LogicException('AuthorizationStateRecord::$state must not be empty.');
        }
        $this->cache->set(
            $this->cacheKey($record->state),
            $this->serialize($record),
            ['oidc_connect_state'],
            $ttl
        );
    }

    public function consume(string $state): ?AuthorizationStateRecord
    {
        if ($state === '') {
            return null;
        }
        $key = $this->cacheKey($state);
        $data = $this->cache->get($key);
        if (!is_array($data)) {
            return null;
        }
        // Best-effort one-time semantics: remove immediately so a second
        // call with the same state can't replay it.
        $this->cache->remove($key);
        return $this->hydrate($data);
    }

    public function discard(string $state): void
    {
        if ($state === '') {
            return;
        }
        $this->cache->remove($this->cacheKey($state));
    }

    /**
     * State is base64url (a-z, A-Z, 0-9, _-) so it would be a valid cache
     * key on its own, but we prefix to avoid collisions with other cache
     * entries that may share the backend.
     */
    private function cacheKey(string $state): string
    {
        return 'state_' . $state;
    }

    /** @return array<string, mixed> */
    private function serialize(AuthorizationStateRecord $r): array
    {
        return [
            'state'              => $r->state,
            'nonce'              => $r->nonce,
            'codeVerifier'       => $r->codeVerifier,
            'redirectUri'        => $r->redirectUri,
            'redirectAfterLogin' => $r->redirectAfterLogin,
            'siteIdentifier'     => $r->siteIdentifier,
            'cookieTokenHash'    => $r->cookieTokenHash,
            'createdAt'          => $r->createdAt,
        ];
    }

    /** @param array<string, mixed> $data */
    private function hydrate(array $data): AuthorizationStateRecord
    {
        return new AuthorizationStateRecord(
            state:              (string)($data['state'] ?? ''),
            nonce:              (string)($data['nonce'] ?? ''),
            codeVerifier:       isset($data['codeVerifier']) ? (string)$data['codeVerifier'] : null,
            redirectUri:        (string)($data['redirectUri'] ?? ''),
            redirectAfterLogin: (string)($data['redirectAfterLogin'] ?? ''),
            siteIdentifier:     (string)($data['siteIdentifier'] ?? ''),
            cookieTokenHash:    (string)($data['cookieTokenHash'] ?? ''),
            createdAt:          (int)($data['createdAt'] ?? 0),
        );
    }
}
