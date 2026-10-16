<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use TYPO3\CMS\Core\Context\Context;
use TYPO3\CMS\Core\Context\UserAspect;
use TYPO3\CMS\Core\Http\RedirectResponse;
use TYPO3\CMS\Core\Site\Entity\Site;
use TYPO3\CMS\Core\Site\Entity\SiteLanguage;
use TYPO3\CMS\Frontend\Authentication\FrontendUserAuthentication;
use WapplerSystems\OidcConnect\Authentication\EndSessionUrlBuilder;
use WapplerSystems\OidcConnect\Configuration\OidcConnectSettingsFactory;
use WapplerSystems\OidcConnect\Http\SiteUrls;
use WapplerSystems\OidcConnect\Session\LogoutContext;

/**
 * `GET <logout route>` ends the TYPO3 session and then the provider
 * session (RP-initiated logout with id_token_hint). The browser lands on
 * the configured logout page, or the site root.
 */
final class FrontendLogoutMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly OidcConnectSettingsFactory $settingsFactory,
        private readonly EndSessionUrlBuilder $endSessionUrlBuilder,
        private readonly LogoutContext $logoutContext,
        private readonly Context $context,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $site = $request->getAttribute('site');
        if (!$site instanceof Site) {
            return $handler->handle($request);
        }
        $settings = $this->settingsFactory->forSite($site);
        if (!$settings->isFrontendEnabled() || !SiteUrls::matchesRoute($request, $settings->route('logout'))) {
            return $handler->handle($request);
        }

        $frontendUser = $request->getAttribute('frontend.user');
        if ($frontendUser instanceof FrontendUserAuthentication && is_array($frontendUser->user)) {
            // Triggers RevokeBindingOnLogout, which hands the ID token over.
            $frontendUser->logoff();
            $this->context->setAspect('frontend.user', new UserAspect());
        }

        $language = $request->getAttribute('language');
        $language = $language instanceof SiteLanguage ? $language : null;
        $postLogoutUrl = $settings->logoutRedirectPageId() > 0
            ? SiteUrls::pageUrl($site, $settings->logoutRedirectPageId(), $language)
            : (string)($language?->getBase() ?? $site->getBase());

        $pending = $this->logoutContext->take('FE');
        $target = null;
        if ($pending !== null && $pending['site'] === $site->getIdentifier()) {
            $target = $this->endSessionUrlBuilder->build($settings, $pending['idToken'], $postLogoutUrl);
        }
        return (new RedirectResponse($target ?? $postLogoutUrl, 303))->withHeader('Cache-Control', 'no-store');
    }
}
