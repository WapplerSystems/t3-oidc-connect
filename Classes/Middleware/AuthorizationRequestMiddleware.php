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
use WapplerSystems\OidcConnect\Authentication\AuthorizationStateRecord;
use WapplerSystems\OidcConnect\Authentication\AuthorizationStateStoreInterface;
use WapplerSystems\OidcConnect\Authentication\AuthorizationUrlBuilder;
use WapplerSystems\OidcConnect\Configuration\OidcConnectSettingsFactory;

/**
 * Frontend middleware that intercepts the configured authorize route
 * (default `/oauth_authorize`) and starts the OIDC Authorization Code
 * Flow: builds the IdP redirect URL, persists the state record for the
 * callback, sets a CSRF cookie, and returns a 302.
 *
 * Trigger:
 *   request path ends with `oidcConnect.authorizeRoute`
 *   AND `oidcConnect.auth.enableFrontend` is true
 *   AND site has a non-empty `oidcConnect.clientId`
 *
 * Return-to-origin:
 *   The caller-supplied `?redirect=<path>` query parameter is remembered
 *   in the state record so the callback can return the user to the page
 *   where they clicked "Login". Only same-host root-relative paths are
 *   accepted (open-redirect mitigation).
 *
 *   TODO: the Frontend Login plugin / view helper (next milestone) MUST
 *   automatically append `?redirect={current request URI}` when it
 *   renders a Login link, so users always land back on their origin.
 *   A Referer-header fallback (validated against the site host) is a
 *   reasonable secondary path for direct hits on the authorize route.
 *
 * CSRF binding: a HTTPOnly+SameSite=Lax cookie `oidc_connect_csrf` with a
 * random token is set on the response. The token's sha256 is persisted in
 * the state record; the callback middleware re-derives the hash from the
 * cookie value to confirm the response is for *this* browser.
 */
final class AuthorizationRequestMiddleware implements MiddlewareInterface, LoggerAwareInterface
{
    use LoggerAwareTrait;

    public const CSRF_COOKIE_NAME = 'oidc_connect_csrf';
    private const STATE_TTL_SECONDS = 600;          // 10 minutes is plenty for the IdP roundtrip

    public function __construct(
        private readonly OidcConnectSettingsFactory $settingsFactory,
        private readonly AuthorizationUrlBuilder $urlBuilder,
        private readonly AuthorizationStateStoreInterface $stateStore,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $site = $request->getAttribute('site');
        if (!$site instanceof Site) {
            return $handler->handle($request);
        }
        $settings = $this->settingsFactory->forSite($site);
        if (!$settings->isFrontendEnabled()) {
            return $handler->handle($request);
        }

        $authorizeRoute = $this->normalisePath($settings->authorizeRoute());
        if ($authorizeRoute === '') {
            return $handler->handle($request);
        }

        $path = '/' . ltrim($request->getUri()->getPath(), '/');
        // Ends-with match makes the route work both at `/oauth_authorize`
        // and `/<lang>/oauth_authorize` (TYPO3 prefixes the language base).
        if (!str_ends_with(rtrim($path, '/'), rtrim($authorizeRoute, '/'))) {
            return $handler->handle($request);
        }

        if ($settings->clientId() === '') {
            $this->logger?->error('oidc-connect: authorize route hit but oidcConnect.clientId is empty for site {id}.', [
                'id' => $site->getIdentifier(),
            ]);
            return new \TYPO3\CMS\Core\Http\Response('OIDC client not configured for this site.', 500);
        }

        $callbackUri = $this->buildCallbackUri($site, $settings->callbackRoute(), $settings->redirectUri());
        $idpLanguage = $this->idpLanguageOf($request);
        $authRequest = $this->urlBuilder->build($settings, $callbackUri, $idpLanguage);

        $redirectAfterLogin = $this->validateLocalPath(
            (string)($request->getQueryParams()['redirect'] ?? '')
        );

        $cookieToken = $this->randomToken(32);
        $this->stateStore->save(
            new AuthorizationStateRecord(
                state: $authRequest->state,
                nonce: $authRequest->nonce,
                codeVerifier: $authRequest->codeVerifier,
                redirectUri: $authRequest->redirectUri,
                redirectAfterLogin: $redirectAfterLogin,
                siteIdentifier: $site->getIdentifier(),
                cookieTokenHash: hash('sha256', $cookieToken),
                createdAt: time(),
            ),
            self::STATE_TTL_SECONDS
        );

        $response = new RedirectResponse($authRequest->url);
        return $response->withHeader('Set-Cookie', $this->buildCsrfCookieHeader(
            $cookieToken,
            $request->getUri()->getScheme() === 'https'
        ));
    }

    private function buildCallbackUri(Site $site, string $callbackRoute, string $explicitRedirectUri): string
    {
        if ($explicitRedirectUri !== '') {
            return $explicitRedirectUri;
        }
        $base = rtrim((string)$site->getBase(), '/');
        return $base . '/' . ltrim($callbackRoute, '/');
    }

    private function idpLanguageOf(ServerRequestInterface $request): ?string
    {
        $language = $request->getAttribute('language');
        if ($language instanceof SiteLanguage) {
            return $language->getLocale()->getLanguageCode() ?: null;
        }
        return null;
    }

    /**
     * Accept only same-site relative paths to prevent open-redirect attacks.
     * Returns the cleaned path on success, empty string on rejection.
     */
    private function validateLocalPath(string $candidate): string
    {
        if ($candidate === '' || str_starts_with($candidate, '//')) {
            return '';
        }
        // Reject anything that parses as an absolute URL — paths only.
        $parts = parse_url($candidate);
        if (!is_array($parts) || isset($parts['host']) || isset($parts['scheme'])) {
            return '';
        }
        return $candidate;
    }

    private function normalisePath(string $route): string
    {
        $route = trim($route);
        if ($route === '') {
            return '';
        }
        return '/' . ltrim($route, '/');
    }

    private function buildCsrfCookieHeader(string $value, bool $secure): string
    {
        $parts = [
            self::CSRF_COOKIE_NAME . '=' . $value,
            'Path=/',
            'HttpOnly',
            'SameSite=Lax',
            'Max-Age=' . self::STATE_TTL_SECONDS,
        ];
        if ($secure) {
            $parts[] = 'Secure';
        }
        return implode('; ', $parts);
    }

    private function randomToken(int $bytes = 32): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }
}
