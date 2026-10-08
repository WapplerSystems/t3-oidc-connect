<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Authentication;

use WapplerSystems\OidcConnect\Configuration\OidcConnectSettings;
use WapplerSystems\OidcConnect\Discovery\WellKnownClient;

/**
 * Builds an OpenID Connect Authorization Code Flow request URL.
 *
 * - Authorization Code Flow with PKCE (S256) by default.
 * - Resolves the authorization endpoint from
 *     1) `oidcConnect.endpoints.authorization` if set, else
 *     2) the discovery document at `<issuer>/.well-known/openid-configuration`.
 * - Generates cryptographically random `state`, `nonce` and PKCE
 *   `code_verifier` (RFC 7636: 43 chars, base64url-safe).
 *
 * Side-effect-free: returns an {@see AuthorizationRequest} value object.
 * Persistence of `state` + `code_verifier` for the callback exchange is
 * the caller's job.
 */
final readonly class AuthorizationUrlBuilder
{
    public function __construct(
        private WellKnownClient $discovery,
    ) {}

    /**
     * @param string|null               $redirectUri   Absolute URL of the OIDC callback on this site.
     *                                                 Falls back to `$settings->redirectUri()` and
     *                                                 throws if neither is provided.
     * @param string|null               $idpLanguage   2-char language code passed to the IdP via
     *                                                 the parameter name configured in
     *                                                 `oidcConnect.auth.authorizeLanguageParameter`.
     * @param array<string, string>     $extraParams   Additional query params to merge into the URL
     *                                                 (e.g. `prompt=login`, `login_hint=...`).
     */
    public function build(
        OidcConnectSettings $settings,
        ?string $redirectUri = null,
        ?string $idpLanguage = null,
        array $extraParams = [],
    ): AuthorizationRequest {
        $redirectUri = $redirectUri ?? $settings->redirectUri();
        if ($redirectUri === '') {
            throw new \LogicException(
                'oidc-connect: no redirect URI given. Pass one to build() or set oidcConnect.redirectUri.'
            );
        }

        $clientId = $settings->clientId();
        if ($clientId === '') {
            throw new \LogicException('oidc-connect: oidcConnect.clientId is empty.');
        }

        $authorizationEndpoint = $this->resolveAuthorizationEndpoint($settings);
        if ($authorizationEndpoint === '') {
            throw new \LogicException(
                'oidc-connect: could not determine authorization endpoint (no override, discovery failed).'
            );
        }

        $state = $this->randomToken();
        $nonce = $this->randomToken();

        $params = [
            'response_type' => 'code',
            'client_id'     => $clientId,
            'redirect_uri'  => $redirectUri,
            'scope'         => implode(' ', $settings->scopes() ?: ['openid']),
            'state'         => $state,
            'nonce'         => $nonce,
        ];

        $codeVerifier = null;
        $codeChallenge = null;
        $codeChallengeMethod = null;
        if ($settings->isPkceEnabled()) {
            $codeVerifier = $this->randomToken(64); // 64 bytes -> ~86 base64url chars (well within RFC 7636 limits)
            $codeChallenge = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');
            $codeChallengeMethod = 'S256';
            $params['code_challenge'] = $codeChallenge;
            $params['code_challenge_method'] = $codeChallengeMethod;
        }

        if ($idpLanguage !== null && $idpLanguage !== '') {
            $paramName = $settings->authorizeLanguageParameter();
            if ($paramName !== '') {
                $params[$paramName] = $idpLanguage;
            }
        }

        foreach ($extraParams as $k => $v) {
            $params[(string)$k] = (string)$v;
        }

        $url = $authorizationEndpoint
            . (str_contains($authorizationEndpoint, '?') ? '&' : '?')
            . http_build_query($params, '', '&', PHP_QUERY_RFC3986);

        return new AuthorizationRequest(
            url: $url,
            state: $state,
            nonce: $nonce,
            codeVerifier: $codeVerifier,
            codeChallenge: $codeChallenge,
            codeChallengeMethod: $codeChallengeMethod,
            redirectUri: $redirectUri,
        );
    }

    private function resolveAuthorizationEndpoint(OidcConnectSettings $settings): string
    {
        $override = $settings->endpoint('authorization');
        if ($override !== '') {
            return $override;
        }
        $issuer = $settings->issuer();
        if ($issuer === '') {
            return '';
        }
        return $this->discovery->discover($issuer)->authorizationEndpoint();
    }

    /**
     * Cryptographically secure random token, encoded base64url without
     * padding. 32 bytes by default → 43 url-safe chars.
     */
    private function randomToken(int $bytes = 32): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }
}
