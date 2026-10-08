<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Configuration;

/**
 * Typed, immutable accessor for the resolved `oidcConnect.*` site-settings
 * of one site. Construct via {@see OidcConnectSettingsFactory::forSite()}
 * which applies context variants first.
 *
 * No defaults are coded here — defaults come from
 * `Configuration/Sets/OidcConnect/settings.yaml`. This class is a pure read
 * facade: if a setting is missing, the getter returns the type-appropriate
 * empty value (empty string, zero, empty array, false).
 */
final readonly class OidcConnectSettings
{
    /**
     * @param array<string, mixed> $data Flat & nested `oidcConnect.*` subtree
     *                                   after variant resolution.
     */
    public function __construct(private array $data) {}

    // --- Connection ---------------------------------------------------------

    public function issuer(): string
    {
        return (string)$this->get('issuer', '');
    }

    public function clientId(): string
    {
        return (string)$this->get('clientId', '');
    }

    public function clientSecret(): string
    {
        return (string)$this->get('clientSecret', '');
    }

    /** @return list<string> */
    public function scopes(): array
    {
        $scopes = $this->get('scopes', []);
        if (is_string($scopes)) {
            $scopes = array_filter(array_map('trim', explode(',', $scopes)));
        }
        return array_values(array_filter(array_map('strval', (array)$scopes)));
    }

    public function redirectUri(): string
    {
        return (string)$this->get('redirectUri', '');
    }

    public function callbackRoute(): string
    {
        return (string)$this->get('callbackRoute', '/oauth_callback');
    }

    public function authorizeRoute(): string
    {
        return (string)$this->get('authorizeRoute', '/oauth_authorize');
    }

    // --- Endpoint overrides (otherwise resolved via .well-known) -----------

    public function endpoint(string $name): string
    {
        return (string)$this->get('endpoints.' . $name, '');
    }

    // --- Auth behaviour ----------------------------------------------------

    public function isFrontendEnabled(): bool       { return (bool)$this->get('auth.enableFrontend', false); }
    public function isBackendEnabled(): bool        { return (bool)$this->get('auth.enableBackend', false); }
    public function isPkceEnabled(): bool           { return (bool)$this->get('auth.enablePkce', true); }
    public function shouldRevokeAccessToken(): bool { return (bool)$this->get('auth.revokeAccessTokenAfterLogin', false); }
    public function isCsrfProtected(): bool         { return (bool)$this->get('auth.csrfProtection', true); }
    public function authorizeLanguageParameter(): string
    {
        return (string)$this->get('auth.authorizeLanguageParameter', 'language');
    }

    // --- User provisioning -------------------------------------------------

    public function usersStoragePid(): int    { return (int)$this->get('users.storagePid', 0); }
    public function usersDefaultGroup(): int  { return (int)$this->get('users.defaultGroup', 0); }
    public function usersMustExistLocally(): bool { return (bool)$this->get('users.mustExistLocally', false); }
    public function reEnableHiddenUsers(): bool   { return (bool)$this->get('users.reEnableHidden', false); }
    public function undeleteUsers(): bool         { return (bool)$this->get('users.undelete', false); }

    // --- Mapping -----------------------------------------------------------

    /** @return array<string, string> column => claim */
    public function mappingFor(string $table): array
    {
        $mapping = $this->get('mapping.' . $table, []);
        if (!is_array($mapping)) {
            return [];
        }
        return array_filter($mapping, static fn($v) => is_string($v) || is_array($v));
    }

    // --- UI ---------------------------------------------------------------

    public function loginPageId(): int          { return (int)$this->get('ui.loginPageId', 0); }
    public function logoutRedirectPageId(): int { return (int)$this->get('ui.logoutRedirectPageId', 0); }

    // --- Raw access (for advanced/forward-compat callers) ------------------

    public function raw(): array
    {
        return $this->data;
    }

    public function has(string $path): bool
    {
        return $this->resolve($path) !== null;
    }

    public function get(string $path, mixed $default = null): mixed
    {
        $value = $this->resolve($path);
        return $value ?? $default;
    }

    private function resolve(string $path): mixed
    {
        $segments = explode('.', $path);
        $value = $this->data;
        foreach ($segments as $segment) {
            if (!is_array($value) || !array_key_exists($segment, $value)) {
                return null;
            }
            $value = $value[$segment];
        }
        return $value;
    }
}
