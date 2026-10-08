<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Authentication;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use TYPO3\CMS\Core\Http\RedirectResponse;
use WapplerSystems\OidcConnect\Configuration\OidcConnectSettings;
use WapplerSystems\OidcConnect\Discovery\DiscoveryException;
use WapplerSystems\OidcConnect\Discovery\ProviderMetadataResolver;
use WapplerSystems\OidcConnect\Token\IdTokenValidator;
use WapplerSystems\OidcConnect\Token\TokenEndpointClient;
use WapplerSystems\OidcConnect\Token\TokenExchangeException;
use WapplerSystems\OidcConnect\Token\TokenValidationException;

/**
 * The two halves of the Authorization Code Flow, shared by frontend and
 * backend: starting it (redirect to the provider) and verifying the
 * callback (state, browser binding, RFC 9207 `iss`, code exchange, ID
 * token, userinfo).
 */
final class OidcFlow implements LoggerAwareInterface
{
    use LoggerAwareTrait;

    public const BINDING_COOKIE = 'oidc_connect_flow';
    private const STATE_TTL = 600;
    private const SILENT_ERRORS = ['login_required', 'interaction_required', 'consent_required', 'account_selection_required'];

    public function __construct(
        private readonly ProviderMetadataResolver $metadataResolver,
        private readonly AuthorizationUrlBuilder $urlBuilder,
        private readonly AuthorizationStateStoreInterface $stateStore,
        private readonly TokenEndpointClient $tokenClient,
        private readonly IdTokenValidator $idTokenValidator,
    ) {}

    /**
     * @param array<string, string> $extraParameters
     * @throws DiscoveryException
     */
    public function start(
        ServerRequestInterface $request,
        OidcConnectSettings $settings,
        string $loginType,
        string $redirectUri,
        string $returnUrl,
        ?string $languageCode = null,
        bool $silent = false,
        array $extraParameters = [],
    ): ResponseInterface {
        $metadata = $this->metadataResolver->resolve($settings);
        $bindingValue = AuthorizationUrlBuilder::randomToken();
        $authorization = $this->urlBuilder->build(
            $settings,
            $metadata,
            $redirectUri,
            $loginType,
            $returnUrl,
            $bindingValue,
            $languageCode,
            $silent,
            $extraParameters,
        );
        $this->stateStore->save($authorization['record'], self::STATE_TTL);

        $response = new RedirectResponse($authorization['url'], 303);
        return $response
            ->withHeader('Cache-Control', 'no-store')
            ->withAddedHeader('Set-Cookie', self::cookie(self::BINDING_COOKIE, $bindingValue, self::STATE_TTL, $request));
    }

    /**
     * @throws CallbackException
     */
    public function verifyCallback(ServerRequestInterface $request, OidcConnectSettings $settings, string $loginType): VerifiedIdentity
    {
        $query = $request->getQueryParams();
        $record = $this->stateStore->consume((string)($query['state'] ?? ''));
        if ($record === null) {
            throw new CallbackException('state_invalid', 'Unknown, expired or replayed state.');
        }
        if ($record->loginType !== $loginType || $record->siteIdentifier !== $settings->siteIdentifier()) {
            throw new CallbackException('state_invalid', 'State belongs to a different login type or site.', $record);
        }
        if (!$record->matchesBrowser((string)($request->getCookieParams()[self::BINDING_COOKIE] ?? ''))) {
            throw new CallbackException('state_invalid', 'State is not bound to this browser.', $record);
        }

        if (isset($query['error'])) {
            $error = (string)$query['error'];
            $reason = in_array($error, self::SILENT_ERRORS, true) ? 'login_required' : 'provider_error';
            throw new CallbackException($reason, sprintf('Provider returned %s: %s', $error, (string)($query['error_description'] ?? '')), $record);
        }

        try {
            $metadata = $this->metadataResolver->resolve($settings);
        } catch (DiscoveryException $e) {
            throw new CallbackException('provider_unavailable', $e->getMessage(), $record, $e);
        }

        // RFC 9207: mix-up attack defence.
        $issParameter = $query['iss'] ?? null;
        if ($issParameter !== null && rtrim((string)$issParameter, '/') !== rtrim($metadata->issuer, '/')) {
            throw new CallbackException('issuer_mismatch', 'iss parameter does not match the configured issuer.', $record);
        }
        if ($issParameter === null && $metadata->issParameterSupported) {
            throw new CallbackException('issuer_mismatch', 'Provider announces the iss parameter, but the response lacks it.', $record);
        }

        $code = (string)($query['code'] ?? '');
        if ($code === '') {
            throw new CallbackException('missing_code', 'Callback without authorization code.', $record);
        }

        try {
            $tokens = $this->tokenClient->exchangeCode($settings, $metadata, $code, $record->redirectUri, $record->codeVerifier);
            $claims = $this->idTokenValidator->validateIdToken(
                (string)$tokens->idToken,
                $settings,
                $metadata,
                $record->nonce,
                $tokens->accessToken,
            );
            if ($settings->useUserinfo()) {
                $userinfo = $this->tokenClient->fetchUserinfo($metadata, $tokens->accessToken);
                if ($userinfo !== []) {
                    if (($userinfo['sub'] ?? null) !== $claims['sub']) {
                        throw new TokenValidationException('Userinfo sub does not match the ID token.', 1747600050);
                    }
                    // Verified ID token claims win over userinfo.
                    $claims = array_replace($userinfo, $claims);
                }
            }
        } catch (TokenExchangeException|TokenValidationException $e) {
            $this->logger?->error('oidc-connect: callback rejected: {error}', ['error' => $e->getMessage()]);
            throw new CallbackException('token_invalid', $e->getMessage(), $record, $e);
        }

        // Access and refresh tokens are deliberately dropped here: nothing in
        // this extension calls APIs on the user's behalf. Revoking the refresh
        // token is not an option either, Keycloak would remove the client from
        // the SSO session and stop sending back-channel logouts for it.

        return new VerifiedIdentity(
            loginType: $loginType,
            siteIdentifier: $settings->siteIdentifier(),
            issuer: $metadata->issuer,
            subject: (string)$claims['sub'],
            sessionId: (string)($claims['sid'] ?? ''),
            claims: $claims,
            idToken: (string)$tokens->idToken,
            returnUrl: $record->returnUrl,
            expiresAt: (int)$claims['exp'],
        );
    }

    public static function cookie(string $name, string $value, int $maxAge, ServerRequestInterface $request): string
    {
        $parts = [$name . '=' . rawurlencode($value), 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=' . $maxAge];
        if ($maxAge <= 0) {
            $parts[] = 'Expires=Thu, 01 Jan 1970 00:00:00 GMT';
        }
        if ($request->getUri()->getScheme() === 'https') {
            $parts[] = 'Secure';
        }
        return implode('; ', $parts);
    }
}
