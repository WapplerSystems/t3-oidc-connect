<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Authentication;

/**
 * Server-side record persisted between the authorization redirect and the
 * OIDC callback. Lifetime is short (default 10 min) — once consumed it
 * MUST be deleted to prevent replay.
 *
 * `cookieTokenHash` is the optional defensive binding to a single browser:
 * the middleware sets a HTTPOnly+SameSite=Lax cookie with a random token
 * and stores `hash('sha256', $token)` here. On callback the cookie value
 * is re-hashed and compared via {@see verifyCookieToken()}. With this
 * binding in place, knowing the URL `state` alone (e.g. by leaking a
 * Referer) is not enough to forge a callback.
 */
final readonly class AuthorizationStateRecord
{
    public function __construct(
        public string $state,
        public string $nonce,
        public ?string $codeVerifier,
        public string $redirectUri,             // where the IdP returns to (the OIDC callback URL)
        public string $redirectAfterLogin = '', // where we send the user once we've created the session
        public string $siteIdentifier = '',
        public string $cookieTokenHash = '',
        public int $createdAt = 0,
    ) {}

    /**
     * @return true if no cookie binding was enforced or the supplied token matches.
     */
    public function verifyCookieToken(string $cookieToken): bool
    {
        if ($this->cookieTokenHash === '') {
            return true;
        }
        return hash_equals($this->cookieTokenHash, hash('sha256', $cookieToken));
    }
}
