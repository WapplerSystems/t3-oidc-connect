<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Configuration;

/**
 * Resolves the client secret of a site without ever storing it in site
 * settings. Lookup order:
 *
 *   1. environment variable named in `oidcConnect.clientSecretEnv`
 *   2. environment variable `OIDC_CONNECT_<SITE_IDENTIFIER>_CLIENT_SECRET`
 *      (site identifier upper-cased, non-alphanumerics replaced by `_`)
 *   3. `$GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['oidc_connect']['clientSecrets'][<site>]`
 *      (for config/system/additional.php)
 *
 * An empty result is valid: public clients authenticate with PKCE only.
 */
final class SecretResolver
{
    public function resolve(string $siteIdentifier, string $envName = ''): string
    {
        foreach ([$envName, self::conventionalEnvName($siteIdentifier)] as $name) {
            if ($name === '') {
                continue;
            }
            $value = $_ENV[$name] ?? $_SERVER[$name] ?? getenv($name);
            if (is_string($value) && $value !== '') {
                return $value;
            }
        }
        $configured = $GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['oidc_connect']['clientSecrets'][$siteIdentifier] ?? '';
        return is_string($configured) ? $configured : '';
    }

    public static function conventionalEnvName(string $siteIdentifier): string
    {
        $normalized = strtoupper((string)preg_replace('/[^A-Za-z0-9]+/', '_', $siteIdentifier));
        return 'OIDC_CONNECT_' . trim($normalized, '_') . '_CLIENT_SECRET';
    }
}
