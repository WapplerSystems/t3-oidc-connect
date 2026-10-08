<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Authentication;

/**
 * Result of {@see AuthorizationUrlBuilder::build()}.
 *
 * `$url` is the IdP redirect target. `$state`, `$nonce`, `$codeVerifier`
 * must be persisted server-side so the callback handler can validate the
 * response. Persistence is the caller's responsibility — typically a
 * short-lived cache record keyed by `$state` plus an HTTPOnly cookie
 * that pins the state to one browser session.
 */
final readonly class AuthorizationRequest
{
    public function __construct(
        public string $url,
        public string $state,
        public string $nonce,
        public ?string $codeVerifier,           // null when PKCE disabled
        public ?string $codeChallenge,
        public ?string $codeChallengeMethod,    // 'S256' or null
        public string $redirectUri,
    ) {}
}
