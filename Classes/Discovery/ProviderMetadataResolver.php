<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Discovery;

use WapplerSystems\OidcConnect\Configuration\OidcConnectSettings;

final class ProviderMetadataResolver
{
    /** @var array<string, ProviderMetadata> */
    private array $runtimeCache = [];

    public function __construct(
        private readonly WellKnownClient $discovery,
    ) {}

    /**
     * @throws DiscoveryException when the issuer is set but discovery fails,
     *                            or when neither issuer nor overrides are configured
     */
    public function resolve(OidcConnectSettings $settings): ProviderMetadata
    {
        $key = $settings->siteIdentifier() . '|' . $settings->issuer();
        if (isset($this->runtimeCache[$key])) {
            return $this->runtimeCache[$key];
        }

        $document = $settings->issuer() !== '' ? $this->discovery->discover($settings->issuer()) : null;

        $pick = static fn(string $override, ?string $discovered): string => $override !== '' ? $override : (string)$discovered;

        $metadata = new ProviderMetadata(
            issuer: $settings->issuer(),
            authorizationEndpoint: $pick($settings->endpoint('authorization'), $document?->authorizationEndpoint()),
            tokenEndpoint: $pick($settings->endpoint('token'), $document?->tokenEndpoint()),
            userinfoEndpoint: $pick($settings->endpoint('userinfo'), $document?->userinfoEndpoint()),
            endSessionEndpoint: $pick($settings->endpoint('endSession'), $document?->endSessionEndpoint()),
            jwksUri: $pick($settings->endpoint('jwks'), $document?->jwksUri()),
            issParameterSupported: $document?->supportsIssParameter() ?? false,
            tokenEndpointAuthMethods: $document?->tokenEndpointAuthMethodsSupported() ?? ['client_secret_basic'],
            signingAlgorithms: $document?->idTokenSigningAlgValuesSupported() ?? [],
        );

        if ($metadata->authorizationEndpoint === '' || $metadata->tokenEndpoint === '') {
            throw new DiscoveryException(
                sprintf('oidc-connect: no authorization/token endpoint for site "%s" (set oidcConnect.issuer).', $settings->siteIdentifier()),
                1747400010
            );
        }
        return $this->runtimeCache[$key] = $metadata;
    }
}
