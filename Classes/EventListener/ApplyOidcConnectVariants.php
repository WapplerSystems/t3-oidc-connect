<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\EventListener;

use TYPO3\CMS\Core\Attribute\AsEventListener;
use TYPO3\CMS\Core\Configuration\Event\SiteConfigurationLoadedEvent;
use WapplerSystems\OidcConnect\Configuration\ContextVariantResolver;

/**
 * Hooks into the site configuration load step (`SiteConfigurationLoadedEvent`)
 * and folds matching `oidcConnect.variants[]` into the top-level
 * `oidcConnect.*` keys BEFORE the SiteSettings object is built and cached.
 *
 * The event fires once per site config.yaml load. The TYPO3 core cache for
 * site configurations is application-context dependent, so a single variant
 * evaluation per cache-build is correct: each environment gets its own
 * cached, resolved variant.
 */
#[AsEventListener(identifier: 'oidc-connect/apply-variants')]
final readonly class ApplyOidcConnectVariants
{
    public function __construct(
        private ContextVariantResolver $resolver,
    ) {}

    public function __invoke(SiteConfigurationLoadedEvent $event): void
    {
        $configuration = $event->getConfiguration();
        $oidcConnect = $configuration['settings']['oidcConnect'] ?? null;

        if (!is_array($oidcConnect) || empty($oidcConnect['variants'])) {
            return;
        }

        $configuration['settings']['oidcConnect'] = $this->resolver->resolve($oidcConnect);
        $event->setConfiguration($configuration);
    }
}
