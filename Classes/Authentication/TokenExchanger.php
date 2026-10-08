<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Authentication;

use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use TYPO3\CMS\Core\Http\RequestFactory;
use WapplerSystems\OidcConnect\Configuration\OidcConnectSettings;
use WapplerSystems\OidcConnect\Discovery\WellKnownClient;

/**
 * Exchanges an Authorization Code for an access token + ID token at the
 * IdP token endpoint (RFC 6749 §4.1.3 with OIDC additions).
 *
 * Client authentication: HTTP Basic (`client_secret_basic`) when a
 * `clientSecret` is configured, otherwise omitted (suitable for public
 * clients in conjunction with PKCE).
 *
 * The token endpoint URL is resolved from
 *   1) `oidcConnect.endpoints.token` if set, else
 *   2) the discovery document at `<issuer>/.well-known/openid-configuration`.
 *
 * Out of scope here:
 *   - ID token signature/claims verification (separate validator class).
 *   - Refresh token usage. The returned TokenSet exposes the refresh
 *     token if the IdP supplied one.
 */
final class TokenExchanger implements LoggerAwareInterface
{
    use LoggerAwareTrait;

    public function __construct(
        private readonly RequestFactory $requestFactory,
        private readonly WellKnownClient $discovery,
    ) {}

    /**
     * @throws TokenExchangeException on any non-2xx response, network
     *         failure, invalid JSON, or missing required fields.
     */
    public function exchange(
        OidcConnectSettings $settings,
        string $code,
        string $redirectUri,
        ?string $codeVerifier = null,
    ): TokenSet {
        if ($code === '') {
            throw new TokenExchangeException('Authorization code is empty.');
        }
        if ($redirectUri === '') {
            throw new TokenExchangeException('redirect_uri is empty.');
        }
        $endpoint = $this->resolveTokenEndpoint($settings);
        if ($endpoint === '') {
            throw new TokenExchangeException('Could not determine token endpoint (no override, discovery failed).');
        }

        $body = [
            'grant_type'   => 'authorization_code',
            'code'         => $code,
            'redirect_uri' => $redirectUri,
            'client_id'    => $settings->clientId(),
        ];
        if ($codeVerifier !== null && $codeVerifier !== '') {
            $body['code_verifier'] = $codeVerifier;
        }

        $options = [
            'form_params' => $body,
            'headers' => [
                'Accept' => 'application/json',
            ],
            'timeout' => 15,
            'http_errors' => false,         // we handle non-2xx ourselves
        ];
        $clientSecret = $settings->clientSecret();
        if ($clientSecret !== '') {
            $options['auth'] = [$settings->clientId(), $clientSecret];
        }

        try {
            $response = $this->requestFactory->request($endpoint, 'POST', $options);
        } catch (\Throwable $e) {
            $this->logger?->error('oidc-connect: token endpoint request failed: {error}', ['error' => $e->getMessage()]);
            throw new TokenExchangeException(
                sprintf('Token endpoint %s unreachable: %s', $endpoint, $e->getMessage()),
                1747500001,
                $e
            );
        }

        $status = $response->getStatusCode();
        $raw = (string)$response->getBody();
        try {
            $decoded = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new TokenExchangeException(
                sprintf('Token endpoint returned non-JSON body (HTTP %d): %s', $status, $e->getMessage()),
                1747500002,
                $e
            );
        }
        if (!is_array($decoded)) {
            throw new TokenExchangeException(
                sprintf('Token endpoint returned non-object body (HTTP %d).', $status),
                1747500003
            );
        }

        if ($status < 200 || $status >= 300) {
            $errCode = (string)($decoded['error'] ?? 'http_' . $status);
            $errDesc = (string)($decoded['error_description'] ?? '');
            throw new TokenExchangeException(
                sprintf('Token endpoint rejected exchange: %s%s', $errCode, $errDesc !== '' ? ' — ' . $errDesc : ''),
                1747500004
            );
        }

        $accessToken = (string)($decoded['access_token'] ?? '');
        if ($accessToken === '') {
            throw new TokenExchangeException('Token response missing access_token.', 1747500005);
        }

        return new TokenSet(
            accessToken: $accessToken,
            idToken: isset($decoded['id_token']) ? (string)$decoded['id_token'] : null,
            refreshToken: isset($decoded['refresh_token']) ? (string)$decoded['refresh_token'] : null,
            tokenType: (string)($decoded['token_type'] ?? 'Bearer'),
            expiresIn: isset($decoded['expires_in']) ? (int)$decoded['expires_in'] : null,
            scope: isset($decoded['scope']) ? (string)$decoded['scope'] : null,
            raw: $decoded,
        );
    }

    private function resolveTokenEndpoint(OidcConnectSettings $settings): string
    {
        $override = $settings->endpoint('token');
        if ($override !== '') {
            return $override;
        }
        $issuer = $settings->issuer();
        if ($issuer === '') {
            return '';
        }
        return $this->discovery->discover($issuer)->tokenEndpoint();
    }
}
