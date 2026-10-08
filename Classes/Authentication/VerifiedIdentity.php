<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Authentication;

/**
 * Result of a fully validated callback: the ID token signature and claims,
 * state, nonce, browser binding and issuer have been checked.
 *
 * Passed from the callback middleware to the authentication service as a
 * request attribute; request attributes cannot be set by clients.
 */
final readonly class VerifiedIdentity
{
    public const REQUEST_ATTRIBUTE = 'oidc_connect.identity';

    /**
     * @param array<string, mixed> $claims ID token claims, merged with userinfo claims
     */
    public function __construct(
        public string $loginType,
        public string $siteIdentifier,
        public string $issuer,
        public string $subject,
        public string $sessionId,
        public array $claims,
        public string $idToken,
        public string $returnUrl,
        public int $expiresAt,
    ) {}

    public function claim(string $path): mixed
    {
        if (array_key_exists($path, $this->claims)) {
            return $this->claims[$path];
        }
        $value = $this->claims;
        foreach (explode('.', $path) as $segment) {
            if (!is_array($value) || !array_key_exists($segment, $value)) {
                return null;
            }
            $value = $value[$segment];
        }
        return $value;
    }
}
