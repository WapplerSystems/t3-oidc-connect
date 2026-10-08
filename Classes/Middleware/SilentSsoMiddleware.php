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
use TYPO3\CMS\Frontend\Authentication\FrontendUserAuthentication;
use WapplerSystems\OidcConnect\Authentication\OidcFlow;
use WapplerSystems\OidcConnect\Configuration\OidcConnectSettingsFactory;
use WapplerSystems\OidcConnect\Http\SiteUrls;

/**
 * Silent SSO (`prompt=none`): an anonymous visitor who already has a
 * session at the provider is logged in without seeing a login page.
 *
 * At most one check per `silentSsoInterval` per browser (cookie), only for
 * top-level GET navigations that accept HTML, never for bots, never on the
 * OIDC routes themselves. A failed check is cheap: the provider answers
 * `login_required` immediately and the visitor is sent back.
 */
final class SilentSsoMiddleware implements MiddlewareInterface, LoggerAwareInterface
{
    use LoggerAwareTrait;

    private const BOT_PATTERN = '/bot|crawl|spider|slurp|facebookexternalhit|preview|monitor|curl|wget|python|httpclient|headless|lighthouse/i';

    public function __construct(
        private readonly OidcConnectSettingsFactory $settingsFactory,
        private readonly OidcFlow $flow,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $site = $request->getAttribute('site');
        if (!$site instanceof Site || !$this->isCandidate($request)) {
            return $handler->handle($request);
        }
        $settings = $this->settingsFactory->forSite($site);
        if (!$settings->isFrontendEnabled() || !$settings->isSilentSsoEnabled()) {
            return $handler->handle($request);
        }
        foreach (['authorize', 'callback', 'logout', 'backchannelLogout'] as $route) {
            if (SiteUrls::matchesRoute($request, $settings->route($route))) {
                return $handler->handle($request);
            }
        }

        $language = $request->getAttribute('language');
        try {
            $response = $this->flow->start(
                $request,
                $settings,
                'FE',
                SiteUrls::routeUrl($site, $settings->route('callback')),
                (string)$request->getUri(),
                $language instanceof SiteLanguage ? $language->getLocale()->getLanguageCode() : null,
                true,
            );
        } catch (\Throwable $e) {
            $this->logger?->warning('oidc-connect: silent SSO check skipped: {error}', ['error' => $e->getMessage()]);
            return $handler->handle($request);
        }
        // Mark the check as done right away, so an aborted round trip cannot loop.
        return $response->withAddedHeader(
            'Set-Cookie',
            OidcFlow::cookie(FrontendCallbackMiddleware::SILENT_CHECK_COOKIE, '1', $settings->silentSsoInterval(), $request)
        );
    }

    private function isCandidate(ServerRequestInterface $request): bool
    {
        if ($request->getMethod() !== 'GET' || isset($request->getCookieParams()[FrontendCallbackMiddleware::SILENT_CHECK_COOKIE])) {
            return false;
        }
        $frontendUser = $request->getAttribute('frontend.user');
        if ($frontendUser instanceof FrontendUserAuthentication && is_array($frontendUser->user)) {
            return false;
        }
        if (!str_contains($request->getHeaderLine('Accept'), 'text/html')
            || $request->getHeaderLine('Sec-Fetch-Mode') === 'cors'
            || in_array($request->getHeaderLine('Sec-Fetch-Dest'), ['iframe', 'frame', 'embed', 'object'], true)
            || $request->getHeaderLine('Purpose') === 'prefetch'
            || $request->getHeaderLine('Sec-Purpose') !== ''
        ) {
            return false;
        }
        $userAgent = $request->getHeaderLine('User-Agent');
        if ($userAgent === '' || preg_match(self::BOT_PATTERN, $userAgent) === 1) {
            return false;
        }
        // Explicit logout, plain TYPO3 logout or an IdP error round trip: do not log back in.
        $query = $request->getQueryParams();
        return !isset($query['logintype']) && !isset($query['oidc_error']);
    }
}
