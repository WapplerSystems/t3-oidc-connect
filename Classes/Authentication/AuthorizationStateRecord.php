<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Authentication;

/**
 * Server-side record of one in-flight authorization request, persisted
 * between the redirect to the provider and the callback. Single use.
 *
 * `browserBindingHash` is the sha256 of a random value stored in an
 * HttpOnly cookie when the flow starts: knowing `state` alone (e.g. from a
 * leaked Referer) is not enough to complete someone else's login.
 */
final readonly class AuthorizationStateRecord
{
    public function __construct(
        public string $state,
        public string $nonce,
        public string $codeVerifier,
        public string $redirectUri,
        public string $loginType = 'FE',
        public string $siteIdentifier = '',
        public string $returnUrl = '',
        public bool $silent = false,
        public string $browserBindingHash = '',
        public int $createdAt = 0,
    ) {}

    public function matchesBrowser(string $bindingValue): bool
    {
        return $this->browserBindingHash !== ''
            && $bindingValue !== ''
            && hash_equals($this->browserBindingHash, hash('sha256', $bindingValue));
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return get_object_vars($this);
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        return new self(
            state: (string)($data['state'] ?? ''),
            nonce: (string)($data['nonce'] ?? ''),
            codeVerifier: (string)($data['codeVerifier'] ?? ''),
            redirectUri: (string)($data['redirectUri'] ?? ''),
            loginType: (string)($data['loginType'] ?? 'FE'),
            siteIdentifier: (string)($data['siteIdentifier'] ?? ''),
            returnUrl: (string)($data['returnUrl'] ?? ''),
            silent: (bool)($data['silent'] ?? false),
            browserBindingHash: (string)($data['browserBindingHash'] ?? ''),
            createdAt: (int)($data['createdAt'] ?? 0),
        );
    }
}
