<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use TYPO3\CMS\Core\Site\Entity\Site;
use TYPO3\CMS\Core\Site\Entity\SiteLanguage;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Frontend\Controller\ErrorController;
use WapplerSystems\OidcConnect\Authentication\OidcFlow;
use WapplerSystems\OidcConnect\Configuration\OidcConnectSettingsFactory;
use WapplerSystems\OidcConnect\Http\SiteUrls;

/**
 * `GET <authorize route>?redirect=<url>` starts the login: redirect to the
 * provider with state, nonce and PKCE. The return URL is validated against
 * the request host; without one, the Referer (same host) or the configured
 * after-login page is used.
 */
final class FrontendAuthorizeMiddleware implements MiddlewareInterface, LoggerAwareInterface
{
    use LoggerAwareTrait;

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
        if (!$settings->isFrontendEnabled() || !SiteUrls::matchesRoute($request, $settings->route('authorize'))) {
            return $handler->handle($request);
        }

        $language = $request->getAttribute('language');
        $language = $language instanceof SiteLanguage ? $language : null;
        $query = $request->getQueryParams();
        $returnUrl = SiteUrls::safeReturnUrl((string)($query['redirect'] ?? ''), $request)
            ?: SiteUrls::safeReturnUrl($request->getHeaderLine('Referer'), $request)
            ?: SiteUrls::defaultReturnUrl($site, $settings, $language);

        $extra = [];
        if (is_string($query['login_hint'] ?? null)) {
            $extra['login_hint'] = mb_substr($query['login_hint'], 0, 255);
        }
        if (in_array($query['prompt'] ?? null, ['login', 'create'], true)) {
            $extra['prompt'] = $query['prompt'];
        }

        try {
            return $this->flow->start(
                $request,
                $settings,
                'FE',
                SiteUrls::routeUrl($site, $settings->route('callback')),
                $returnUrl,
                $language?->getLocale()->getLanguageCode(),
                false,
                $extra,
            );
        } catch (\Throwable $e) {
            $this->logger?->error('oidc-connect: cannot start login for site {site}: {error}', [
                'site' => $site->getIdentifier(),
                'error' => $e->getMessage(),
            ]);
            return GeneralUtility::makeInstance(ErrorController::class)
                ->unavailableAction($request, 'The login service is currently not available.');
        }
    }
}
