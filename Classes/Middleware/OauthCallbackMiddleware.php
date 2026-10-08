<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Middleware;

use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use TYPO3\CMS\Core\Http\RedirectResponse;
use TYPO3\CMS\Core\Http\Response;
use TYPO3\CMS\Core\Site\Entity\Site;
use WapplerSystems\OidcConnect\Authentication\AuthorizationStateStoreInterface;
use WapplerSystems\OidcConnect\Authentication\TokenExchangeException;
use WapplerSystems\OidcConnect\Authentication\TokenExchanger;
use WapplerSystems\OidcConnect\Configuration\OidcConnectSettingsFactory;
use WapplerSystems\OidcConnect\Event\AfterTokenExchangedEvent;
use WapplerSystems\OidcConnect\Event\BeforeTokenExchangeEvent;

/**
 * Frontend middleware for the OIDC redirect target (default
 * `/oauth_callback`). Validates the response, exchanges the
 * authorization code for tokens, dispatches an event for downstream
 * user-resolution logic, and redirects the user to `redirectAfterLogin`
 * (the page they started from).
 *
 * Sequence:
 *   1. Detect path = `oidcConnect.callbackRoute` AND
 *      `oidcConnect.auth.enableFrontend = true`.
 *   2. Handle IdP error: `?error=` parameter (e.g. user denied consent).
 *   3. Consume state from the store (one-time). Reject if missing.
 *   4. Verify CSRF cookie token against the stored hash. Reject on mismatch.
 *   5. Dispatch {@see BeforeTokenExchangeEvent} — listeners may abort.
 *   6. Exchange `code` for tokens via {@see TokenExchanger}.
 *   7. Dispatch {@see AfterTokenExchangedEvent}. Listeners do the heavy
 *      lifting (userinfo, fe_users session) and may replace the redirect.
 *   8. Redirect to `state.redirectAfterLogin` or `/` and clear the CSRF cookie.
 *
 * Out of scope (next milestone):
 *   - ID token signature/claims validation (separate `IdTokenValidator`).
 *   - Userinfo fetch and fe_users lookup/create. Both belong to the
 *     listener attached to AfterTokenExchangedEvent.
 */
final class OauthCallbackMiddleware implements MiddlewareInterface, LoggerAwareInterface
{
    use LoggerAwareTrait;

    public function __construct(
        private readonly OidcConnectSettingsFactory $settingsFactory,
        private readonly AuthorizationStateStoreInterface $stateStore,
        private readonly TokenExchanger $tokenExchanger,
        private readonly EventDispatcherInterface $eventDispatcher,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $site = $request->getAttribute('site');
        if (!$site instanceof Site) {
            return $handler->handle($request);
        }
        $settings = $this->settingsFactory->forSite($site);
        if (!$settings->isFrontendEnabled()) {
            return $handler->handle($request);
        }
        $callbackRoute = '/' . ltrim(trim($settings->callbackRoute()), '/');
        if ($callbackRoute === '/') {
            return $handler->handle($request);
        }
        $path = '/' . ltrim($request->getUri()->getPath(), '/');
        if (!str_ends_with(rtrim($path, '/'), rtrim($callbackRoute, '/'))) {
            return $handler->handle($request);
        }

        $query = $request->getQueryParams();
        if (!empty($query['error'])) {
            $this->logger?->warning('oidc-connect: IdP returned error={error} desc={desc}', [
                'error' => (string)$query['error'],
                'desc' => (string)($query['error_description'] ?? ''),
            ]);
            return $this->failure(
                'authentication_failed',
                (string)$query['error'],
                (string)($query['error_description'] ?? '')
            );
        }

        $state = (string)($query['state'] ?? '');
        $code  = (string)($query['code'] ?? '');
        if ($state === '' || $code === '') {
            return $this->failure('missing_parameters', 'state/code missing on callback');
        }

        $record = $this->stateStore->consume($state);
        if ($record === null) {
            $this->logger?->warning('oidc-connect: callback state not found or already consumed.');
            return $this->failure('state_invalid', 'state not found or replayed');
        }

        $cookieToken = $request->getCookieParams()[AuthorizationRequestMiddleware::CSRF_COOKIE_NAME] ?? '';
        if (!$record->verifyCookieToken((string)$cookieToken)) {
            $this->logger?->warning('oidc-connect: CSRF cookie mismatch on callback (state={state}).', ['state' => $state]);
            return $this->failure('csrf_mismatch', 'CSRF cookie does not match the state record');
        }

        $beforeEvent = new BeforeTokenExchangeEvent($request, $site, $settings, $record, $code);
        $this->eventDispatcher->dispatch($beforeEvent);
        if ($beforeEvent->isAborted()) {
            return $this->failure('aborted', $beforeEvent->abortReason());
        }

        try {
            $tokens = $this->tokenExchanger->exchange(
                $settings,
                $code,
                $record->redirectUri,
                $record->codeVerifier,
            );
        } catch (TokenExchangeException $e) {
            $this->logger?->error('oidc-connect: token exchange failed: {error}', ['error' => $e->getMessage()]);
            return $this->failure('token_exchange_failed', $e->getMessage());
        }

        $afterEvent = new AfterTokenExchangedEvent($request, $site, $settings, $record, $tokens);
        $this->eventDispatcher->dispatch($afterEvent);
        $response = $afterEvent->getOverrideResponse() ?? $this->buildSuccessRedirect($site, $record->redirectAfterLogin);

        return $this->withClearedCsrfCookie($response, $request->getUri()->getScheme() === 'https');
    }

    private function buildSuccessRedirect(Site $site, string $redirectAfterLogin): ResponseInterface
    {
        if ($redirectAfterLogin !== '' && $this->isLocalPath($redirectAfterLogin)) {
            return new RedirectResponse($redirectAfterLogin);
        }
        // Fallback: site root.
        return new RedirectResponse((string)$site->getBase());
    }

    private function failure(string $code, string $reason, string $detail = ''): ResponseInterface
    {
        // TODO: render a proper themed error page once the UI layer exists.
        // For now a minimal JSON response — sufficient for debugging and
        // any front-end JS that ever hits this URL directly.
        $body = json_encode([
            'error' => $code,
            'reason' => $reason,
            'detail' => $detail,
        ], JSON_THROW_ON_ERROR);
        $response = new Response(null, 400);
        $response = $response->withHeader('Content-Type', 'application/json');
        $response->getBody()->write($body);
        return $response;
    }

    private function withClearedCsrfCookie(ResponseInterface $response, bool $secure): ResponseInterface
    {
        $parts = [
            AuthorizationRequestMiddleware::CSRF_COOKIE_NAME . '=',
            'Path=/',
            'HttpOnly',
            'SameSite=Lax',
            'Max-Age=0',
            'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
        ];
        if ($secure) {
            $parts[] = 'Secure';
        }
        return $response->withAddedHeader('Set-Cookie', implode('; ', $parts));
    }

    private function isLocalPath(string $candidate): bool
    {
        if ($candidate === '' || str_starts_with($candidate, '//')) {
            return false;
        }
        $parts = parse_url($candidate);
        if (!is_array($parts) || isset($parts['host']) || isset($parts['scheme'])) {
            return false;
        }
        return true;
    }
}
