<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\EventListener;

use TYPO3\CMS\Core\Attribute\AsEventListener;
use TYPO3\CMS\Core\Authentication\Event\BeforeUserLogoutEvent;
use WapplerSystems\OidcConnect\Session\LogoutContext;
use WapplerSystems\OidcConnect\Session\SessionBindingRepository;

/**
 * Any local logout (felogin, `?logintype=logout`, backend logout, our own
 * logout route) closes the binding of an OIDC session and remembers the ID
 * token, so the logout middlewares can end the provider session too.
 */
#[AsEventListener(identifier: 'oidc-connect/revoke-binding-on-logout')]
final readonly class RevokeBindingOnLogout
{
    public function __construct(
        private SessionBindingRepository $bindings,
        private LogoutContext $logoutContext,
    ) {}

    public function __invoke(BeforeUserLogoutEvent $event): void
    {
        $session = $event->getUserSession();
        $data = $session?->get(SessionBindingRepository::SESSION_DATA_KEY);
        $bindingUid = is_array($data) ? (int)($data['binding'] ?? 0) : 0;
        if ($bindingUid <= 0) {
            return;
        }
        $binding = $this->bindings->find($bindingUid);
        if ($binding === null) {
            return;
        }
        if ((int)$binding['revoked'] === 0 && (string)$binding['id_token'] !== '') {
            $this->logoutContext->remember($event->getUser()->loginType, (string)$binding['site'], (string)$binding['id_token']);
        }
        $this->bindings->revoke($bindingUid);
    }
}
