<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Configuration;

/**
 * Typed, immutable accessor for the resolved `oidcConnect.*` site settings of
 * one site. Construct via {@see OidcConnectSettingsFactory::forSite()}, which
 * applies context variants and resolves the client secret first.
 *
 * Defaults come from `Configuration/Sets/OidcConnect/settings.definitions.yaml`;
 * the fallbacks below only matter when the set is not included.
 */
final readonly class OidcConnectSettings
{
    /**
     * @param array<string, mixed> $data the `oidcConnect` subtree after variant resolution
     */
    public function __construct(
        private string $siteIdentifier,
        private array $data,
        #[\SensitiveParameter]
        private string $clientSecret = '',
    ) {}

    public function siteIdentifier(): string
    {
        return $this->siteIdentifier;
    }

    /**
     * True once the minimum for a working flow is configured.
     */
    public function isConfigured(): bool
    {
        return $this->clientId() !== ''
            && ($this->issuer() !== '' || $this->endpoint('authorization') !== '');
    }

    // --- Connection ---------------------------------------------------------

    public function issuer(): string
    {
        return rtrim((string)$this->get('issuer', ''), '/');
    }

    public function clientId(): string
    {
        return (string)$this->get('clientId', '');
    }

    public function clientSecret(): string
    {
        return $this->clientSecret;
    }

    public function clientSecretEnv(): string
    {
        return (string)$this->get('clientSecretEnv', '');
    }

    /** @return list<string> */
    public function scopes(): array
    {
        $scopes = $this->stringList('scopes');
        if (!in_array('openid', $scopes, true)) {
            array_unshift($scopes, 'openid');
        }
        return $scopes;
    }

    public function tokenEndpointAuthMethod(): string
    {
        return (string)$this->get('tokenEndpointAuthMethod', 'auto');
    }

    public function endpoint(string $name): string
    {
        return (string)$this->get('endpoints.' . $name, '');
    }

    // --- Routes ---------------------------------------------------------------

    public function route(string $name): string
    {
        $defaults = [
            'authorize' => '/oauth_authorize',
            'callback' => '/oauth_callback',
            'logout' => '/oauth_logout',
            'backchannelLogout' => '/oauth_backchannel_logout',
        ];
        $route = trim((string)$this->get('routes.' . $name, $defaults[$name] ?? ''));
        return $route === '' ? '' : '/' . ltrim($route, '/');
    }

    // --- Auth behaviour -------------------------------------------------------

    public function isFrontendEnabled(): bool
    {
        return (bool)$this->get('auth.enableFrontend', true) && $this->isConfigured();
    }

    public function useUserinfo(): bool
    {
        return (bool)$this->get('auth.useUserinfo', true);
    }

    public function isBackchannelLogoutEnabled(): bool
    {
        return (bool)$this->get('auth.backchannelLogout', true);
    }

    public function isSilentSsoEnabled(): bool
    {
        return (bool)$this->get('auth.silentSso', false);
    }

    public function silentSsoInterval(): int
    {
        return max(60, (int)$this->get('auth.silentSsoInterval', 3600));
    }

    public function languageParameter(): string
    {
        return (string)$this->get('auth.languageParameter', 'ui_locales');
    }

    public function idpHint(): string
    {
        return (string)$this->get('auth.idpHint', '');
    }

    public function clockSkew(): int
    {
        return max(0, (int)$this->get('auth.clockSkew', 60));
    }

    /** @return list<string> */
    public function allowedSigningAlgorithms(): array
    {
        $algorithms = $this->stringList('auth.allowedSigningAlgorithms');
        // Symmetric and unsigned algorithms are never acceptable for ID tokens
        // validated against a public JWKS.
        return array_values(array_filter(
            $algorithms ?: ['RS256'],
            static fn(string $alg): bool => $alg !== 'none' && !str_starts_with($alg, 'HS')
        ));
    }

    // --- User provisioning ----------------------------------------------------

    /**
     * Provisioning options for the given login type ('FE' or 'BE').
     */
    public function userOptions(string $loginType): UserProvisioningOptions
    {
        if ($loginType === 'BE') {
            return new UserProvisioningOptions(
                table: 'be_users',
                groupTable: 'be_groups',
                storagePid: 0,
                defaultGroups: $this->intList('backend.defaultGroups'),
                createUsers: (bool)$this->get('backend.createUsers', false),
                reEnableDisabled: false,
                undelete: false,
                linkByField: (string)$this->get('backend.linkByField', 'email'),
                linkByClaim: 'email',
                linkRequireVerifiedEmail: true,
                groupsClaim: (string)$this->get('backend.groupsClaim', ''),
                mapping: $this->mappingFor('be_users'),
                groupMapping: $this->groupMappingFor('be_groups'),
            );
        }
        return new UserProvisioningOptions(
            table: 'fe_users',
            groupTable: 'fe_groups',
            storagePid: (int)$this->get('users.storagePid', 0),
            defaultGroups: $this->intList('users.defaultGroups'),
            createUsers: !(bool)$this->get('users.mustExistLocally', false),
            reEnableDisabled: (bool)$this->get('users.reEnableDisabled', false),
            undelete: (bool)$this->get('users.undelete', false),
            linkByField: (string)$this->get('users.linkByField', ''),
            linkByClaim: (string)$this->get('users.linkByClaim', 'email'),
            linkRequireVerifiedEmail: (bool)$this->get('users.linkRequireVerifiedEmail', true),
            groupsClaim: (string)$this->get('users.groupsClaim', ''),
            mapping: $this->mappingFor('fe_users'),
            groupMapping: $this->groupMappingFor('fe_groups'),
        );
    }

    public function isBackendEnabled(): bool
    {
        return (bool)$this->get('backend.enable', false) && $this->isConfigured();
    }

    // --- UI -------------------------------------------------------------------

    public function afterLoginPageId(): int
    {
        return (int)$this->get('ui.afterLoginPageId', 0);
    }

    public function logoutRedirectPageId(): int
    {
        return (int)$this->get('ui.logoutRedirectPageId', 0);
    }

    public function errorPageId(): int
    {
        return (int)$this->get('ui.errorPageId', 0);
    }

    // --- Raw access -------------------------------------------------------------

    /** @return array<string, mixed> */
    public function raw(): array
    {
        return $this->data;
    }

    public function get(string $path, mixed $default = null): mixed
    {
        $value = $this->data;
        foreach (explode('.', $path) as $segment) {
            if (!is_array($value) || !array_key_exists($segment, $value)) {
                return $default;
            }
            $value = $value[$segment];
        }
        return $value ?? $default;
    }

    /** @return array<string, string> column => claim */
    private function mappingFor(string $table): array
    {
        $mapping = $this->get('mapping.' . $table, []);
        if (!is_array($mapping)) {
            return [];
        }
        $result = [];
        foreach ($mapping as $column => $claim) {
            if (is_string($column) && is_scalar($claim) && (string)$claim !== '') {
                $result[$column] = (string)$claim;
            }
        }
        return $result;
    }

    /** @return array<string, list<int>> pattern => group uids */
    private function groupMappingFor(string $table): array
    {
        $mapping = $this->get('groupMapping.' . $table, []);
        if (!is_array($mapping)) {
            return [];
        }
        $result = [];
        foreach ($mapping as $pattern => $groups) {
            $uids = is_array($groups) ? $groups : explode(',', (string)$groups);
            $uids = array_values(array_filter(array_map('intval', $uids), static fn(int $uid): bool => $uid > 0));
            if ((string)$pattern !== '' && $uids !== []) {
                $result[(string)$pattern] = $uids;
            }
        }
        return $result;
    }

    /** @return list<string> */
    private function stringList(string $path): array
    {
        $value = $this->get($path, []);
        if (is_string($value)) {
            $value = explode(',', $value);
        }
        if (!is_array($value)) {
            return [];
        }
        // Settings merging re-keys lists; keep declaration order.
        ksort($value, SORT_NUMERIC);
        return array_values(array_filter(array_map(static fn($v): string => trim((string)$v), $value), static fn(string $v): bool => $v !== ''));
    }

    /** @return list<int> */
    private function intList(string $path): array
    {
        return array_values(array_filter(array_map('intval', $this->stringList($path)), static fn(int $v): bool => $v > 0));
    }
}
