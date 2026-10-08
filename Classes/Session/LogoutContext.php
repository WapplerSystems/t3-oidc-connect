<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Session;

use TYPO3\CMS\Core\SingletonInterface;

/**
 * Request-scoped hand-over between the logout event listener (which sees
 * the session before it is destroyed) and the middleware that sends the
 * browser to the provider's end_session_endpoint afterwards.
 */
final class LogoutContext implements SingletonInterface
{
    /** @var array<string, array{site: string, idToken: string}> by login type */
    private array $pending = [];

    public function remember(string $loginType, string $siteIdentifier, string $idToken): void
    {
        $this->pending[$loginType] = ['site' => $siteIdentifier, 'idToken' => $idToken];
    }

    /** @return array{site: string, idToken: string}|null */
    public function take(string $loginType): ?array
    {
        $pending = $this->pending[$loginType] ?? null;
        unset($this->pending[$loginType]);
        return $pending;
    }
}
