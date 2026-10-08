<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Authentication;

use WapplerSystems\OidcConnect\Configuration\OidcConnectSettings;
use WapplerSystems\OidcConnect\Discovery\ProviderMetadataResolver;

/**
 * OpenID Connect RP-Initiated Logout 1.0. With `id_token_hint`, Keycloak
 * (18+) ends the session without a confirmation page and honours the
 * registered `post_logout_redirect_uri`.
 */
final readonly class EndSessionUrlBuilder
{
    public function __construct(
        private ProviderMetadataResolver $metadataResolver,
    ) {}

    /**
     * @return string|null null if the provider has no end_session_endpoint
     */
    public function build(OidcConnectSettings $settings, string $idToken, string $postLogoutRedirectUri): ?string
    {
        try {
            $endpoint = $this->metadataResolver->resolve($settings)->endSessionEndpoint;
        } catch (\Throwable) {
            return null;
        }
        if ($endpoint === '') {
            return null;
        }
        $parameters = array_filter([
            'client_id' => $settings->clientId(),
            'id_token_hint' => $idToken,
            'post_logout_redirect_uri' => $postLogoutRedirectUri,
        ], static fn(string $value): bool => $value !== '');
        return $endpoint . (str_contains($endpoint, '?') ? '&' : '?') . http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
    }
}
