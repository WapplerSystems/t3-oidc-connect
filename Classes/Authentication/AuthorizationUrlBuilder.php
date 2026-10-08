<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Authentication;

use WapplerSystems\OidcConnect\Configuration\OidcConnectSettings;
use WapplerSystems\OidcConnect\Discovery\ProviderMetadata;

/**
 * Builds the authorization request URL (Authorization Code Flow, PKCE S256
 * always on, RFC 9700 §2.1.1) together with the state record that has to be
 * persisted for the callback.
 */
final class AuthorizationUrlBuilder
{
    /**
     * @param array<string, string> $extraParameters e.g. login_hint, kc_action
     * @return array{url: string, record: AuthorizationStateRecord}
     */
    public function build(
        OidcConnectSettings $settings,
        ProviderMetadata $metadata,
        string $redirectUri,
        string $loginType,
        string $returnUrl,
        string $browserBindingValue,
        ?string $languageCode = null,
        bool $silent = false,
        array $extraParameters = [],
    ): array {
        $state = self::randomToken();
        $nonce = self::randomToken();
        $codeVerifier = self::randomToken(64);

        $parameters = [
            'response_type' => 'code',
            'client_id' => $settings->clientId(),
            'redirect_uri' => $redirectUri,
            'scope' => implode(' ', $settings->scopes()),
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256',
        ];
        if ($silent) {
            $parameters['prompt'] = 'none';
        }
        if ($languageCode !== null && $languageCode !== '') {
            foreach (array_filter(array_map('trim', explode(',', $settings->languageParameter()))) as $name) {
                $parameters[$name] = $languageCode;
            }
        }
        if ($settings->idpHint() !== '') {
            $parameters['kc_idp_hint'] = $settings->idpHint();
        }
        foreach ($extraParameters as $name => $value) {
            if (!isset($parameters[$name]) && $value !== '') {
                $parameters[$name] = $value;
            }
        }

        $endpoint = $metadata->authorizationEndpoint;
        $url = $endpoint . (str_contains($endpoint, '?') ? '&' : '?') . http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);

        return [
            'url' => $url,
            'record' => new AuthorizationStateRecord(
                state: $state,
                nonce: $nonce,
                codeVerifier: $codeVerifier,
                redirectUri: $redirectUri,
                loginType: $loginType,
                siteIdentifier: $settings->siteIdentifier(),
                returnUrl: $returnUrl,
                silent: $silent,
                browserBindingHash: hash('sha256', $browserBindingValue),
                createdAt: time(),
            ),
        ];
    }

    /**
     * Cryptographically random base64url token (32 bytes → 43 chars).
     */
    public static function randomToken(int $bytes = 32): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }
}
