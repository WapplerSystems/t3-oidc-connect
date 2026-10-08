<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Backend;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use TYPO3\CMS\Backend\Attribute\AsController;
use TYPO3\CMS\Backend\Routing\UriBuilder;
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;
use TYPO3\CMS\Core\Http\RedirectResponse;
use WapplerSystems\OidcConnect\Authentication\VerifiedIdentity;
use WapplerSystems\OidcConnect\Session\SessionBindingRepository;

/**
 * Target of the public backend route `oidc_connect_callback`. By the time
 * it runs, {@see BackendOidcMiddleware} has verified the callback and the
 * core has (or has not) logged the user in.
 */
#[AsController]
final class CallbackController implements LoggerAwareInterface
{
    use LoggerAwareTrait;

    public function __construct(
        private readonly SessionBindingRepository $bindings,
        private readonly UriBuilder $uriBuilder,
    ) {}

    public function __invoke(ServerRequestInterface $request): ResponseInterface
    {
        $identity = $request->getAttribute(VerifiedIdentity::REQUEST_ATTRIBUTE);
        $backendUser = $GLOBALS['BE_USER'] ?? null;
        $user = $backendUser instanceof BackendUserAuthentication ? $backendUser->user : null;

        if (!$identity instanceof VerifiedIdentity
            || !is_array($user)
            || ($user['tx_oidcconnect_subject'] ?? '') !== $identity->subject
            || ($user['tx_oidcconnect_issuer'] ?? '') !== $identity->issuer
        ) {
            $this->logger?->notice('oidc-connect: backend login refused for {sub}', [
                'sub' => $identity instanceof VerifiedIdentity ? $identity->subject : '-',
            ]);
            return new RedirectResponse((string)$this->uriBuilder->buildUriFromRoute('login', [
                'loginProvider' => OidcLoginProvider::IDENTIFIER,
                'oidc_error' => 'not_authorized',
            ]), 303);
        }

        $bindingUid = $this->bindings->create($identity, (int)$user['uid']);
        $backendUser->setAndSaveSessionData(SessionBindingRepository::SESSION_DATA_KEY, ['binding' => $bindingUid]);

        return new RedirectResponse((string)$this->uriBuilder->buildUriFromRoute('main'), 303);
    }
}
