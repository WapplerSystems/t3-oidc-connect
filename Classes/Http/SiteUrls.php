<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Http;

use Psr\Http\Message\ServerRequestInterface;
use TYPO3\CMS\Core\Site\Entity\Site;
use TYPO3\CMS\Core\Site\Entity\SiteLanguage;
use WapplerSystems\OidcConnect\Configuration\OidcConnectSettings;

/**
 * URL helpers for the frontend flow: route matching, absolute route URLs
 * and open-redirect-safe return URLs.
 */
final class SiteUrls
{
    /**
     * True if the request path is the given route below the site base or
     * below a language base (`/oauth_callback`, `/en/oauth_callback`).
     */
    public static function matchesRoute(ServerRequestInterface $request, string $route): bool
    {
        if ($route === '') {
            return false;
        }
        $path = rtrim('/' . ltrim($request->getUri()->getPath(), '/'), '/');
        return $path === rtrim($route, '/') || str_ends_with($path, rtrim($route, '/'));
    }

    /**
     * Absolute URL of a route, always on the default-language base so the
     * redirect URIs registered at the provider stay stable.
     */
    public static function routeUrl(Site $site, string $route): string
    {
        return rtrim((string)$site->getBase(), '/') . $route;
    }

    public static function pageUrl(Site $site, int $pageId, ?SiteLanguage $language = null): string
    {
        $parameters = $language !== null ? ['_language' => $language] : [];
        return (string)$site->getRouter()->generateUri($pageId, $parameters);
    }

    /**
     * Accepts root-relative paths and absolute URLs on the request's own
     * host; everything else becomes ''.
     */
    public static function safeReturnUrl(string $candidate, ServerRequestInterface $request): string
    {
        $candidate = trim($candidate);
        if ($candidate === '' || str_contains($candidate, '\\') || preg_match('/[\x00-\x1F]/', $candidate)) {
            return '';
        }
        if (str_starts_with($candidate, '/') && !str_starts_with($candidate, '//')) {
            return $candidate;
        }
        $parts = parse_url($candidate);
        if (!is_array($parts) || !in_array(strtolower($parts['scheme'] ?? ''), ['http', 'https'], true)) {
            return '';
        }
        $requestUri = $request->getUri();
        if (strtolower($parts['host'] ?? '') !== strtolower($requestUri->getHost())
            || ($parts['port'] ?? null) !== $requestUri->getPort()
        ) {
            return '';
        }
        return $candidate;
    }

    /**
     * Where to go after login when the caller did not say: the configured
     * page, otherwise the site root.
     */
    public static function defaultReturnUrl(Site $site, OidcConnectSettings $settings, ?SiteLanguage $language): string
    {
        if ($settings->afterLoginPageId() > 0) {
            try {
                return self::pageUrl($site, $settings->afterLoginPageId(), $language);
            } catch (\Throwable) {
            }
        }
        return (string)($language?->getBase() ?? $site->getBase());
    }
}
