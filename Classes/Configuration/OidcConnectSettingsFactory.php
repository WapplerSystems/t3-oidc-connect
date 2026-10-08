<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Configuration;

use TYPO3\CMS\Core\Site\Entity\Site;

/**
 * Builds an {@see OidcConnectSettings} value object from a {@see Site}.
 *
 * Variants are NOT applied here — they have already been merged into the
 * `oidcConnect.*` subtree at site-configuration load time by
 * {@see \WapplerSystems\OidcConnect\EventListener\ApplyOidcConnectVariants}.
 */
final readonly class OidcConnectSettingsFactory
{
    public function forSite(Site $site): OidcConnectSettings
    {
        $data = $site->getSettings()->get('oidcConnect', []);
        if (!is_array($data)) {
            $data = [];
        }
        // Remove the variants array if it accidentally survived (it should
        // have been consumed by the SiteConfigurationLoadedEvent listener,
        // but be defensive — leaving raw variant data in the value object
        // would be confusing).
        unset($data['variants']);
        return new OidcConnectSettings($data);
    }
}
