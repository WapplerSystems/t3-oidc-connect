<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Backend;

use Psr\Http\Message\UriInterface;

/**
 * Backend URLs that must be registered at the provider. Built by hand
 * (and not with the backend UriBuilder) so that the CLI provisioning
 * command produces exactly the same strings as the login flow.
 */
final class BackendUrls
{
    public const CALLBACK_PATH = '/oidc-connect/callback';

    public static function callbackUrl(string $origin): string
    {
        return rtrim($origin, '/') . self::entryPoint() . self::CALLBACK_PATH;
    }

    public static function loginUrl(string $origin): string
    {
        return rtrim($origin, '/') . self::entryPoint() . '/login';
    }

    public static function origin(UriInterface $uri): string
    {
        $port = $uri->getPort();
        return $uri->getScheme() . '://' . $uri->getHost() . ($port !== null ? ':' . $port : '');
    }

    private static function entryPoint(): string
    {
        $entryPoint = (string)($GLOBALS['TYPO3_CONF_VARS']['BE']['entryPoint'] ?? '/typo3');
        return '/' . trim($entryPoint, '/');
    }
}
