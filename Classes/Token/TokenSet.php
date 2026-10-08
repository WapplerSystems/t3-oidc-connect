<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Token;

/**
 * The token response returned by an IdP's token endpoint after a
 * successful Authorization Code exchange. Fields follow RFC 6749 §5.1
 * plus the OIDC `id_token` extension.
 *
 * `raw` holds the full decoded JSON payload so callers can access
 * provider-specific extras (e.g. `not-before-policy`, `session_state`)
 * without bloating this class.
 */
final readonly class TokenSet
{
    public function __construct(
        public string $accessToken,
        public ?string $idToken,
        public ?string $refreshToken,
        public string $tokenType,
        public ?int $expiresIn,
        public ?string $scope,
        /** @var array<string, mixed> */
        public array $raw,
    ) {}
}
