<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Configuration;

use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use Symfony\Component\ExpressionLanguage\SyntaxError;
use TYPO3\CMS\Core\ExpressionLanguage\Resolver;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * Resolves baseVariants-style context overlays inside the `oidcConnect`
 * settings subtree. Each variant has a `condition` string evaluated by the
 * TYPO3 ExpressionLanguage `site` resolver (same engine that handles
 * Site::resolveBaseVariant). The first matching variant is deep-merged on
 * top of the base settings; `variants` itself is dropped from the result.
 *
 * Example YAML:
 *   oidcConnect:
 *     clientId: prod-client
 *     clientSecret: '%env(OIDC_CLIENT_SECRET)%'
 *     variants:
 *       - condition: 'applicationContext matches "/^Development/"'
 *         clientId: dev-client
 *         clientSecret: '%env(OIDC_DEV_CLIENT_SECRET)%'
 *       - condition: 'applicationContext matches "/^Production\\/Stage/"'
 *         clientId: stage-client
 *
 * Pure data transform; no I/O. Safe to call at site-configuration load time.
 */
final class ContextVariantResolver implements LoggerAwareInterface
{
    use LoggerAwareTrait;

    /**
     * @param array<string, mixed> $oidcConnect The `oidcConnect` settings subtree.
     * @return array<string, mixed>             The merged subtree without `variants`.
     */
    public function resolve(array $oidcConnect): array
    {
        $variants = $oidcConnect['variants'] ?? null;
        if (!is_array($variants) || $variants === []) {
            return $oidcConnect;
        }
        unset($oidcConnect['variants']);

        $resolver = GeneralUtility::makeInstance(Resolver::class, 'site', []);
        foreach ($variants as $variant) {
            if (!is_array($variant) || !isset($variant['condition'])) {
                continue;
            }
            try {
                if ((bool)$resolver->evaluate((string)$variant['condition'])) {
                    unset($variant['condition']);
                    return $this->deepMerge($oidcConnect, $variant);
                }
            } catch (SyntaxError $e) {
                $this->logger?->warning(
                    'oidc-connect: invalid variant condition "{condition}": {error}',
                    [
                        'condition' => $variant['condition'] ?? '',
                        'error' => $e->getMessage(),
                    ]
                );
            }
        }
        return $oidcConnect;
    }

    /**
     * Deep merge override into base. Scalars in `override` win over `base`;
     * arrays are recursively merged (associative) or replaced (numeric/list).
     */
    private function deepMerge(array $base, array $override): array
    {
        foreach ($override as $key => $value) {
            if (is_array($value) && isset($base[$key]) && is_array($base[$key]) && !$this->isList($value) && !$this->isList($base[$key])) {
                $base[$key] = $this->deepMerge($base[$key], $value);
            } else {
                $base[$key] = $value;
            }
        }
        return $base;
    }

    private function isList(array $array): bool
    {
        return array_keys($array) === range(0, count($array) - 1);
    }
}
