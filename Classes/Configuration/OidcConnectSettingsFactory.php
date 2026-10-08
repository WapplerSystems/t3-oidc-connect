<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Configuration;

use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;
use TYPO3\CMS\Core\Exception\SiteNotFoundException;
use TYPO3\CMS\Core\Site\Entity\Site;
use TYPO3\CMS\Core\Site\SiteFinder;

/**
 * Builds {@see OidcConnectSettings} for a site.
 *
 * Context variants are resolved here and not at site-configuration load
 * time: TYPO3 v14 reads site settings from `settings.yaml`, so a
 * SiteConfigurationLoadedEvent listener never sees them.
 */
final class OidcConnectSettingsFactory
{
    /** @var array<string, OidcConnectSettings> */
    private array $runtimeCache = [];

    public function __construct(
        private readonly ContextVariantResolver $variantResolver,
        private readonly SecretResolver $secretResolver,
        private readonly SiteFinder $siteFinder,
        private readonly ExtensionConfiguration $extensionConfiguration,
    ) {}

    public function forSite(Site $site): OidcConnectSettings
    {
        $identifier = $site->getIdentifier();
        if (isset($this->runtimeCache[$identifier])) {
            return $this->runtimeCache[$identifier];
        }
        $data = $site->getSettings()->get('oidcConnect', []);
        $data = $this->variantResolver->resolve(is_array($data) ? $data : []);
        unset($data['clientSecret']);

        return $this->runtimeCache[$identifier] = new OidcConnectSettings(
            $identifier,
            $data,
            $this->secretResolver->resolve($identifier, (string)($data['clientSecretEnv'] ?? '')),
        );
    }

    /**
     * The site whose settings drive the backend login. The backend has no
     * site context, so this is chosen in the extension configuration
     * (`backendSite`); without it, the first site with `backend.enable`
     * wins.
     */
    public function forBackend(): ?OidcConnectSettings
    {
        try {
            $configured = (string)($this->extensionConfiguration->get('oidc_connect', 'backendSite') ?? '');
        } catch (\Throwable) {
            $configured = '';
        }
        if ($configured !== '') {
            try {
                $settings = $this->forSite($this->siteFinder->getSiteByIdentifier($configured));
                return $settings->isBackendEnabled() ? $settings : null;
            } catch (SiteNotFoundException) {
                return null;
            }
        }
        foreach ($this->siteFinder->getAllSites() as $site) {
            $settings = $this->forSite($site);
            if ($settings->isBackendEnabled()) {
                return $settings;
            }
        }
        return null;
    }

    public function siteFor(OidcConnectSettings $settings): Site
    {
        return $this->siteFinder->getSiteByIdentifier($settings->siteIdentifier());
    }
}
