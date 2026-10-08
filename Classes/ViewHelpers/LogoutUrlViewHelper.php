<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\ViewHelpers;

/**
 * URL that ends the TYPO3 session and the provider session.
 *
 *     <a href="{oidc:logoutUrl()}">Log out</a>
 */
final class LogoutUrlViewHelper extends AbstractRouteUrlViewHelper
{
    public function render(): string
    {
        $request = $this->getRequest();
        return $request === null ? '' : $this->buildRouteUrl($request, 'logout');
    }
}
