<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Backend;

use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\DependencyInjection\Attribute\Autoconfigure;
use TYPO3\CMS\Backend\LoginProvider\LoginProviderInterface;
use TYPO3\CMS\Core\View\ViewInterface;
use TYPO3\CMS\Fluid\View\FluidViewAdapter;

/**
 * Backend login tab "Single Sign-On". The core login form is submitted
 * with `oidc_connect=1`; {@see BackendOidcMiddleware} turns that into the
 * redirect to the provider.
 */
#[Autoconfigure(public: true)]
final class OidcLoginProvider implements LoginProviderInterface
{
    public const IDENTIFIER = 1747900001;

    public function modifyView(ServerRequestInterface $request, ViewInterface $view): string
    {
        $view->assignMultiple([
            'enablePasswordReset' => false,
            'oidcError' => preg_replace('/[^a-z_]/', '', (string)($request->getQueryParams()['oidc_error'] ?? '')),
        ]);
        if ($view instanceof FluidViewAdapter) {
            $paths = $view->getRenderingContext()->getTemplatePaths();
            $paths->setTemplateRootPaths([...$paths->getTemplateRootPaths(), 'EXT:oidc_connect/Resources/Private/Templates/']);
        }
        return 'Backend/Login';
    }
}
