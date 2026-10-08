<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Discovery;

/**
 * Effective provider endpoints and capabilities: explicit overrides from
 * the site settings win over the discovery document.
 */
final readonly class ProviderMetadata
{
    /**
     * @param list<string> $tokenEndpointAuthMethods
     * @param list<string> $signingAlgorithms
     */
    public function __construct(
        public string $issuer,
        public string $authorizationEndpoint,
        public string $tokenEndpoint,
        public string $userinfoEndpoint,
        public string $endSessionEndpoint,
        public string $jwksUri,
        public bool $issParameterSupported,
        public array $tokenEndpointAuthMethods,
        public array $signingAlgorithms,
    ) {}
}
