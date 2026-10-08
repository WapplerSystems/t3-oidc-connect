<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Backend;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use TYPO3\CMS\Backend\Routing\Route;
use TYPO3\CMS\Core\Http\RedirectResponse;
use WapplerSystems\OidcConnect\Authentication\EndSessionUrlBuilder;
use WapplerSystems\OidcConnect\Configuration\OidcConnectSettingsFactory;
use WapplerSystems\OidcConnect\Session\LogoutContext;

/**
 * After a backend logout of an OIDC session, sends the browser through the
 * provider's end_session_endpoint and back to the backend login.
 */
final class BackendLogoutMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly OidcConnectSettingsFactory $settingsFactory,
        private readonly EndSessionUrlBuilder $endSessionUrlBuilder,
        private readonly LogoutContext $logoutContext,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $response = $handler->handle($request);

        $route = $request->getAttribute('route');
        if (!$route instanceof Route || $route->getOption('_identifier') !== 'logout') {
            return $response;
        }
        $pending = $this->logoutContext->take('BE');
        $settings = $pending !== null ? $this->settingsFactory->forBackend() : null;
        if ($settings === null || $pending['site'] !== $settings->siteIdentifier()) {
            return $response;
        }
        $target = $this->endSessionUrlBuilder->build(
            $settings,
            $pending['idToken'],
            BackendUrls::loginUrl(BackendUrls::origin($request->getUri())),
        );
        if ($target === null) {
            return $response;
        }
        $redirect = new RedirectResponse($target, 303);
        // Keep the cookie headers of the core logout (session removal).
        foreach ($response->getHeader('Set-Cookie') as $cookie) {
            $redirect = $redirect->withAddedHeader('Set-Cookie', $cookie);
        }
        return $redirect;
    }
}
