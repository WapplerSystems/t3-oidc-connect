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
use TYPO3\CMS\Core\Site\Entity\SiteLanguage;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Frontend\Controller\ErrorController;
use WapplerSystems\OidcConnect\Authentication\CallbackException;
use WapplerSystems\OidcConnect\Authentication\OidcFlow;
use WapplerSystems\OidcConnect\Authentication\VerifiedIdentity;
use WapplerSystems\OidcConnect\Configuration\OidcConnectSettings;
use WapplerSystems\OidcConnect\Configuration\OidcConnectSettingsFactory;
use WapplerSystems\OidcConnect\Http\SiteUrls;

/**
 * Runs before `typo3/cms-frontend/authentication`.
 *
 * Verifies the callback completely and then hands the request on as an
 * active login (`logintype=login`) carrying the {@see VerifiedIdentity}.
 * The core frontend authentication logs the user in through
 * {@see \WapplerSystems\OidcConnect\Service\OidcAuthenticationService};
 * {@see FrontendLoginFinisherMiddleware} answers with the redirect, and the
 * core appends the session cookie to it on the way back.
 */
final class FrontendCallbackMiddleware implements MiddlewareInterface, LoggerAwareInterface
{
    use LoggerAwareTrait;

    public const SILENT_CHECK_COOKIE = 'oidc_connect_sso';

    public function __construct(
        private readonly OidcConnectSettingsFactory $settingsFactory,
        private readonly OidcFlow $flow,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $site = $request->getAttribute('site');
        if (!$site instanceof Site) {
            return $handler->handle($request);
        }
        $settings = $this->settingsFactory->forSite($site);
        if (!$settings->isFrontendEnabled() || !SiteUrls::matchesRoute($request, $settings->route('callback'))) {
            return $handler->handle($request);
        }

        try {
            $identity = $this->flow->verifyCallback($request, $settings, 'FE');
        } catch (CallbackException $e) {
            return $this->clearFlowCookie($this->failure($e, $request, $site, $settings), $request);
        }

        $request = $request
            ->withAttribute(VerifiedIdentity::REQUEST_ATTRIBUTE, $identity)
            ->withQueryParams(['logintype' => 'login']);

        return $this->clearFlowCookie($handler->handle($request), $request);
    }

    private function failure(CallbackException $e, ServerRequestInterface $request, Site $site, OidcConnectSettings $settings): ResponseInterface
    {
        if (!$e->isSilentFailure()) {
            $this->logger?->warning('oidc-connect: frontend callback failed ({reason}): {detail}', [
                'reason' => $e->reason,
                'detail' => $e->getMessage(),
            ]);
        }
        if ($e->record?->silent === true) {
            // A silent check never shows an error: remember it and go back.
            $response = new RedirectResponse(SiteUrls::safeReturnUrl($e->record->returnUrl, $request) ?: (string)$site->getBase(), 303);
            return $response->withAddedHeader('Set-Cookie', OidcFlow::cookie(self::SILENT_CHECK_COOKIE, '1', $settings->silentSsoInterval(), $request));
        }
        if ($settings->errorPageId() > 0) {
            $language = $request->getAttribute('language');
            $url = SiteUrls::pageUrl($site, $settings->errorPageId(), $language instanceof SiteLanguage ? $language : null);
            return new RedirectResponse($url . (str_contains($url, '?') ? '&' : '?') . 'oidc_error=' . rawurlencode($e->reason), 303);
        }
        return GeneralUtility::makeInstance(ErrorController::class)
            ->accessDeniedAction($request, 'Login failed (' . $e->reason . ').');
    }

    private function clearFlowCookie(ResponseInterface $response, ServerRequestInterface $request): ResponseInterface
    {
        return $response->withAddedHeader('Set-Cookie', OidcFlow::cookie(OidcFlow::BINDING_COOKIE, '', 0, $request));
    }
}
