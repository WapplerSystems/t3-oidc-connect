<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use TYPO3\CMS\Core\Http\JsonResponse;
use TYPO3\CMS\Core\Http\Response;
use TYPO3\CMS\Core\Site\Entity\Site;
use WapplerSystems\OidcConnect\Configuration\OidcConnectSettingsFactory;
use WapplerSystems\OidcConnect\Discovery\ProviderMetadataResolver;
use WapplerSystems\OidcConnect\Http\SiteUrls;
use WapplerSystems\OidcConnect\Session\SessionBindingRepository;
use WapplerSystems\OidcConnect\Token\IdTokenValidator;

/**
 * OpenID Connect Back-Channel Logout 1.0 receiver.
 *
 * `POST <backchannel route>` with a `logout_token` from the provider marks
 * all matching session bindings (frontend and backend) as revoked;
 * {@see SessionRevocationMiddleware} ends those sessions on their next
 * request.
 */
final class BackchannelLogoutMiddleware implements MiddlewareInterface, LoggerAwareInterface
{
    use LoggerAwareTrait;

    public function __construct(
        private readonly OidcConnectSettingsFactory $settingsFactory,
        private readonly ProviderMetadataResolver $metadataResolver,
        private readonly IdTokenValidator $validator,
        private readonly SessionBindingRepository $bindings,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $site = $request->getAttribute('site');
        if (!$site instanceof Site) {
            return $handler->handle($request);
        }
        $settings = $this->settingsFactory->forSite($site);
        if (!$settings->isConfigured()
            || !$settings->isBackchannelLogoutEnabled()
            || !SiteUrls::matchesRoute($request, $settings->route('backchannelLogout'))
        ) {
            return $handler->handle($request);
        }
        if ($request->getMethod() !== 'POST') {
            return (new Response(null, 405))->withHeader('Allow', 'POST');
        }

        $body = $request->getParsedBody();
        $logoutToken = is_array($body) ? (string)($body['logout_token'] ?? '') : '';
        if ($logoutToken === '') {
            return $this->error('invalid_request', 'logout_token missing');
        }

        try {
            $metadata = $this->metadataResolver->resolve($settings);
            $claims = $this->validator->validateLogoutToken($logoutToken, $settings, $metadata);
        } catch (\Throwable $e) {
            $this->logger?->warning('oidc-connect: back-channel logout rejected: {error}', ['error' => $e->getMessage()]);
            return $this->error('invalid_request', 'logout_token rejected');
        }

        $count = $this->bindings->revokeByProviderSession(
            $metadata->issuer,
            (string)($claims['sid'] ?? ''),
            (string)($claims['sub'] ?? ''),
        );
        $this->logger?->info('oidc-connect: back-channel logout revoked {count} session(s) for sid {sid}', [
            'count' => $count,
            'sid' => (string)($claims['sid'] ?? '-'),
        ]);

        return (new Response(null, 200))->withHeader('Cache-Control', 'no-store');
    }

    private function error(string $error, string $description): ResponseInterface
    {
        return (new JsonResponse(['error' => $error, 'error_description' => $description], 400))
            ->withHeader('Cache-Control', 'no-store');
    }
}
