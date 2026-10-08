<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Discovery;

/**
 * Immutable view on a fetched OpenID Connect discovery document
 * (`/.well-known/openid-configuration`).
 */
final readonly class OidcDiscoveryDocument
{
    /** @param array<string, mixed> $raw */
    public function __construct(private array $raw) {}

    public function issuer(): string
    {
        return (string)($this->raw['issuer'] ?? '');
    }

    public function authorizationEndpoint(): string
    {
        return (string)($this->raw['authorization_endpoint'] ?? '');
    }

    public function tokenEndpoint(): string
    {
        return (string)($this->raw['token_endpoint'] ?? '');
    }

    public function userinfoEndpoint(): string
    {
        return (string)($this->raw['userinfo_endpoint'] ?? '');
    }

    public function endSessionEndpoint(): string
    {
        return (string)($this->raw['end_session_endpoint'] ?? '');
    }

    public function revocationEndpoint(): string
    {
        return (string)($this->raw['revocation_endpoint'] ?? '');
    }

    public function jwksUri(): string
    {
        return (string)($this->raw['jwks_uri'] ?? '');
    }

    public function supportsIssParameter(): bool
    {
        return (bool)($this->raw['authorization_response_iss_parameter_supported'] ?? false);
    }

    public function supportsBackchannelLogout(): bool
    {
        return (bool)($this->raw['backchannel_logout_supported'] ?? false);
    }

    /** @return list<string> */
    public function tokenEndpointAuthMethodsSupported(): array
    {
        // RFC 8414: default is client_secret_basic when omitted.
        return $this->list('token_endpoint_auth_methods_supported') ?: ['client_secret_basic'];
    }

    /** @return list<string> */
    public function codeChallengeMethodsSupported(): array
    {
        return $this->list('code_challenge_methods_supported');
    }

    /** @return list<string> */
    public function idTokenSigningAlgValuesSupported(): array
    {
        return $this->list('id_token_signing_alg_values_supported');
    }

    /** @return array<string, mixed> */
    public function raw(): array
    {
        return $this->raw;
    }

    /** @return list<string> */
    private function list(string $key): array
    {
        $values = $this->raw[$key] ?? [];
        return is_array($values) ? array_values(array_map('strval', $values)) : [];
    }
}
