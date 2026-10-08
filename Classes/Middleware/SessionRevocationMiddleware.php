<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use TYPO3\CMS\Core\Authentication\AbstractUserAuthentication;
use TYPO3\CMS\Core\Http\RedirectResponse;
use TYPO3\CMS\Core\Http\Response;
use WapplerSystems\OidcConnect\Session\LogoutContext;
use WapplerSystems\OidcConnect\Session\SessionBindingRepository;

/**
 * Ends TYPO3 sessions whose provider session was terminated through
 * back-channel logout. Registered for frontend and backend, right after
 * the respective authentication middleware; costs one primary-key lookup
 * per request of an OIDC-authenticated user.
 */
final class SessionRevocationMiddleware implements MiddlewareInterface, LoggerAwareInterface
{
    use LoggerAwareTrait;

    public function __construct(
        private readonly SessionBindingRepository $bindings,
        private readonly LogoutContext $logoutContext,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $user = $request->getAttribute('frontend.user') ?? $GLOBALS['BE_USER'] ?? null;
        if (!$user instanceof AbstractUserAuthentication || !is_array($user->user)) {
            return $handler->handle($request);
        }
        $data = $user->getSession()->get(SessionBindingRepository::SESSION_DATA_KEY);
        $bindingUid = is_array($data) ? (int)($data['binding'] ?? 0) : 0;
        if ($bindingUid <= 0 || !$this->bindings->isRevoked($bindingUid)) {
            return $handler->handle($request);
        }

        $this->logger?->info('oidc-connect: ending {type} session of user {uid} after back-channel logout', [
            'type' => $user->loginType,
            'uid' => $user->user['uid'] ?? 0,
        ]);
        $user->logoff();
        // The provider session is already gone: no end_session redirect needed.
        $this->logoutContext->take($user->loginType);

        if (in_array($request->getMethod(), ['GET', 'HEAD'], true)) {
            return new RedirectResponse((string)$request->getUri(), 303);
        }
        return new Response(null, 401);
    }
}
