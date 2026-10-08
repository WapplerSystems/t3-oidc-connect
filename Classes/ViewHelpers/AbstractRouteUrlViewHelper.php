<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\ViewHelpers;

use Psr\Http\Message\ServerRequestInterface;
use TYPO3\CMS\Core\Site\Entity\Site;
use TYPO3\CMS\Core\Site\Entity\SiteLanguage;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3Fluid\Fluid\Core\ViewHelper\AbstractViewHelper;
use WapplerSystems\OidcConnect\Configuration\OidcConnectSettingsFactory;

abstract class AbstractRouteUrlViewHelper extends AbstractViewHelper
{
    protected function getRequest(): ?ServerRequestInterface
    {
        if ($this->renderingContext->hasAttribute(ServerRequestInterface::class)) {
            return $this->renderingContext->getAttribute(ServerRequestInterface::class);
        }
        return null;
    }

    /**
     * Route below the current language base, so the provider shows its
     * pages in the visitor's language.
     *
     * @param array<string, string> $parameters
     */
    protected function buildRouteUrl(ServerRequestInterface $request, string $route, array $parameters = []): string
    {
        $site = $request->getAttribute('site');
        if (!$site instanceof Site) {
            return '';
        }
        $settings = GeneralUtility::makeInstance(OidcConnectSettingsFactory::class)->forSite($site);
        if (!$settings->isFrontendEnabled()) {
            return '';
        }
        $language = $request->getAttribute('language');
        $base = $language instanceof SiteLanguage ? $language->getBase() : $site->getBase();
        $url = rtrim((string)$base, '/') . $settings->route($route);
        return $parameters === [] ? $url : $url . '?' . http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
    }
}
