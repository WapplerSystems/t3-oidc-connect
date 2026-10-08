<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Backend;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use TYPO3\CMS\Backend\Routing\Route;
use TYPO3\CMS\Core\Http\RedirectResponse;
use WapplerSystems\OidcConnect\Authentication\CallbackException;
use WapplerSystems\OidcConnect\Authentication\OidcFlow;
use WapplerSystems\OidcConnect\Authentication\VerifiedIdentity;
use WapplerSystems\OidcConnect\Configuration\OidcConnectSettingsFactory;

/**
 * Backend side of the flow; runs after backend routing and before
 * `typo3/cms-backend/authentication`.
 *
 *  - login form submitted with `oidc_connect=1` → redirect to the provider
 *  - callback route → verify, then hand on as active login
 *    (`login_status=login`) carrying the {@see VerifiedIdentity}
 */
final class BackendOidcMiddleware implements MiddlewareInterface, LoggerAwareInterface
{
    use LoggerAwareTrait;

    public function __construct(
        private readonly OidcConnectSettingsFactory $settingsFactory,
        private readonly OidcFlow $flow,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $route = $request->getAttribute('route');
        $routeIdentifier = $route instanceof Route ? (string)$route->getOption('_identifier') : '';
        $isLoginSubmit = $routeIdentifier === 'login'
            && $request->getMethod() === 'POST'
            && is_array($request->getParsedBody())
            && ($request->getParsedBody()['oidc_connect'] ?? '') === '1';
        if (!$isLoginSubmit && $routeIdentifier !== 'oidc_connect_callback') {
            return $handler->handle($request);
        }

        $settings = $this->settingsFactory->forBackend();
        $origin = BackendUrls::origin($request->getUri());
        if ($settings === null) {
            return new RedirectResponse(BackendUrls::loginUrl($origin) . '?oidc_error=not_configured', 303);
        }

        if ($isLoginSubmit) {
            try {
                return $this->flow->start(
                    $request,
                    $settings,
                    'BE',
                    BackendUrls::callbackUrl($origin),
                    '',
                );
            } catch (\Throwable $e) {
                $this->logger?->error('oidc-connect: cannot start backend login: {error}', ['error' => $e->getMessage()]);
                return new RedirectResponse(BackendUrls::loginUrl($origin) . '?oidc_error=provider_unavailable', 303);
            }
        }

        try {
            $identity = $this->flow->verifyCallback($request, $settings, 'BE');
        } catch (CallbackException $e) {
            $this->logger?->warning('oidc-connect: backend callback failed ({reason}): {detail}', [
                'reason' => $e->reason,
                'detail' => $e->getMessage(),
            ]);
            $response = new RedirectResponse(BackendUrls::loginUrl($origin) . '?loginProvider=' . OidcLoginProvider::IDENTIFIER . '&oidc_error=' . rawurlencode($e->reason), 303);
            return $response->withAddedHeader('Set-Cookie', OidcFlow::cookie(OidcFlow::BINDING_COOKIE, '', 0, $request));
        }

        $request = $request
            ->withAttribute(VerifiedIdentity::REQUEST_ATTRIBUTE, $identity)
            ->withQueryParams(['login_status' => 'login']);
        return $handler->handle($request)
            ->withAddedHeader('Set-Cookie', OidcFlow::cookie(OidcFlow::BINDING_COOKIE, '', 0, $request));
    }
}
