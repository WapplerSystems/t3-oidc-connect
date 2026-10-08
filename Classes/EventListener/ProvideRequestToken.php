<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\EventListener;

use TYPO3\CMS\Core\Attribute\AsEventListener;
use TYPO3\CMS\Core\Authentication\Event\BeforeRequestTokenProcessedEvent;
use TYPO3\CMS\Core\Security\RequestToken;
use WapplerSystems\OidcConnect\Authentication\VerifiedIdentity;

/**
 * The core accepts an active login only with a request token of scope
 * `core/user-auth/<fe|be>`. A login form carries one; the OIDC callback
 * cannot, but state, nonce and the browser-bound cookie already give the
 * same CSRF guarantee. The token is only provided when the request carries
 * a {@see VerifiedIdentity}, which clients cannot inject.
 */
#[AsEventListener(identifier: 'oidc-connect/provide-request-token')]
final class ProvideRequestToken
{
    public function __invoke(BeforeRequestTokenProcessedEvent $event): void
    {
        $identity = $event->getRequest()->getAttribute(VerifiedIdentity::REQUEST_ATTRIBUTE);
        $loginType = $event->getUser()->loginType;
        if ($identity instanceof VerifiedIdentity && $identity->loginType === $loginType) {
            $event->setRequestToken(RequestToken::create('core/user-auth/' . strtolower($loginType)));
        }
    }
}
