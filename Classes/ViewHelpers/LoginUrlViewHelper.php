<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\ViewHelpers;

/**
 * URL that starts the OIDC login and returns to the given (or current) URL.
 *
 *     <html xmlns:oidc="http://typo3.org/ns/WapplerSystems/OidcConnect/ViewHelpers" data-namespace-typo3-fluid="true">
 *     <a href="{oidc:loginUrl()}">Log in</a>
 *     <a href="{oidc:loginUrl(redirect: '/members/')}">Log in</a>
 */
final class LoginUrlViewHelper extends AbstractRouteUrlViewHelper
{
    public function initializeArguments(): void
    {
        $this->registerArgument('redirect', 'string', 'Return URL after login; default: the current URL', false, '');
        $this->registerArgument('prompt', 'string', '"login" forces re-authentication, "create" opens the registration (Keycloak 22+)', false, '');
    }

    public function render(): string
    {
        $request = $this->getRequest();
        if ($request === null) {
            return '';
        }
        $parameters = ['redirect' => (string)$this->arguments['redirect'] ?: (string)$request->getUri()];
        if ($this->arguments['prompt'] !== '') {
            $parameters['prompt'] = (string)$this->arguments['prompt'];
        }
        return $this->buildRouteUrl($request, 'authorize', $parameters);
    }
}
