<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use TYPO3\CMS\Core\Http\RedirectResponse;
use TYPO3\CMS\Core\Site\Entity\Site;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Frontend\Authentication\FrontendUserAuthentication;
use TYPO3\CMS\Frontend\Controller\ErrorController;
use WapplerSystems\OidcConnect\Authentication\VerifiedIdentity;
use WapplerSystems\OidcConnect\Configuration\OidcConnectSettingsFactory;
use WapplerSystems\OidcConnect\Http\SiteUrls;
use WapplerSystems\OidcConnect\Session\SessionBindingRepository;

/**
 * Runs right after `typo3/cms-frontend/authentication` and completes a
 * callback request: binds the new TYPO3 session to the provider session
 * and redirects to the return URL. The callback path is never rendered as
 * a page.
 */
final class FrontendLoginFinisherMiddleware implements MiddlewareInterface, LoggerAwareInterface
{
    use LoggerAwareTrait;

    public function __construct(
        private readonly SessionBindingRepository $bindings,
        private readonly OidcConnectSettingsFactory $settingsFactory,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $identity = $request->getAttribute(VerifiedIdentity::REQUEST_ATTRIBUTE);
        if (!$identity instanceof VerifiedIdentity || $identity->loginType !== 'FE') {
            return $handler->handle($request);
        }

        $frontendUser = $request->getAttribute('frontend.user');
        $user = $frontendUser instanceof FrontendUserAuthentication ? $frontendUser->user : null;
        if (!is_array($user)
            || ($user['tx_oidcconnect_subject'] ?? '') !== $identity->subject
            || ($user['tx_oidcconnect_issuer'] ?? '') !== $identity->issuer
        ) {
            $this->logger?->notice('oidc-connect: verified identity {sub} was not logged in (no matching local account or login refused)', [
                'sub' => $identity->subject,
            ]);
            return GeneralUtility::makeInstance(ErrorController::class)
                ->accessDeniedAction($request, 'Your account is not authorized for this website.');
        }

        $bindingUid = $this->bindings->create($identity, (int)$user['uid']);
        $frontendUser->setAndSaveSessionData(SessionBindingRepository::SESSION_DATA_KEY, ['binding' => $bindingUid]);

        $response = (new RedirectResponse(SiteUrls::safeReturnUrl($identity->returnUrl, $request) ?: '/', 303))
            ->withHeader('Cache-Control', 'no-store');
        // Pages viewed before the login may sit in the browser cache in their
        // logged-out state (TYPO3 sends max-age for anonymous visitors); the
        // visitor would see them without the login until a hard reload.
        $site = $request->getAttribute('site');
        if ($site instanceof Site && $this->settingsFactory->forSite($site)->clearBrowserCache()) {
            $response = $response->withHeader('Clear-Site-Data', '"cache"');
        }
        return $response;
    }
}
