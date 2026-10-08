<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Discovery;

/**
 * Immutable view on a fetched OpenID-Connect Discovery document
 * (`/.well-known/openid-configuration`). Exposes the small subset of
 * fields oidc-connect actually consumes; everything else is reachable
 * via {@see raw()}.
 */
final readonly class OidcDiscoveryDocument
{
    /** @param array<string, mixed> $raw */
    public function __construct(private array $raw) {}

    public function issuer(): string                 { return (string)($this->raw['issuer'] ?? ''); }
    public function authorizationEndpoint(): string  { return (string)($this->raw['authorization_endpoint'] ?? ''); }
    public function tokenEndpoint(): string          { return (string)($this->raw['token_endpoint'] ?? ''); }
    public function userinfoEndpoint(): string       { return (string)($this->raw['userinfo_endpoint'] ?? ''); }
    public function endSessionEndpoint(): string     { return (string)($this->raw['end_session_endpoint'] ?? ''); }
    public function revocationEndpoint(): string     { return (string)($this->raw['revocation_endpoint'] ?? ''); }
    public function jwksUri(): string                { return (string)($this->raw['jwks_uri'] ?? ''); }
    public function introspectionEndpoint(): string  { return (string)($this->raw['introspection_endpoint'] ?? ''); }

    /** @return list<string> */
    public function codeChallengeMethodsSupported(): array
    {
        $values = $this->raw['code_challenge_methods_supported'] ?? [];
        return array_values(array_map('strval', (array)$values));
    }

    /** @return list<string> */
    public function scopesSupported(): array
    {
        $values = $this->raw['scopes_supported'] ?? [];
        return array_values(array_map('strval', (array)$values));
    }

    /** @return array<string, mixed> */
    public function raw(): array
    {
        return $this->raw;
    }
}
