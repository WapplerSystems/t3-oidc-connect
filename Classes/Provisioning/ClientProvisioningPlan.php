<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Provisioning;

use TYPO3\CMS\Core\Site\Entity\Site;
use WapplerSystems\OidcConnect\Backend\BackendUrls;
use WapplerSystems\OidcConnect\Configuration\OidcConnectSettings;
use WapplerSystems\OidcConnect\Http\SiteUrls;

/**
 * Immutable plan for the Keycloak ClientRepresentation derived from one site.
 *
 * Existing values from another environment are always kept and merged with
 * the current context. Destructive flags are never added by this class.
 */
final readonly class ClientProvisioningPlan
{
    /**
     * @param list<string> $redirectUris
     * @param list<string> $postLogoutRedirectUris
     * @param list<string> $webOrigins
     */
    public function __construct(
        public string $clientId,
        public array $redirectUris,
        public array $postLogoutRedirectUris,
        public array $webOrigins,
        public string $backchannelLogoutUrl,
    ) {}

    public static function forSettings(OidcConnectSettings $settings, Site $site): self
    {
        $origin = BackendUrls::origin($site->getBase());

        $redirectUris = [
            SiteUrls::routeUrl($site, $settings->route('callback')),
        ];
        if ($settings->isBackendEnabled()) {
            $redirectUris[] = BackendUrls::callbackUrl($origin);
        }

        return new self(
            $settings->clientId(),
            $redirectUris,
            [$origin . '/*'],
            [$origin],
            $settings->isBackchannelLogoutEnabled()
                ? SiteUrls::routeUrl($site, $settings->route('backchannelLogout'))
                : '',
        );
    }

    /**
     * Returns the full representation to send to Keycloak. Existing entries
     * are never removed, because other TYPO3 contexts share the same client.
     */
    public function mergeInto(?array $existing): array
    {
        if ($existing === null) {
            $result = [
                'clientId' => $this->clientId,
                'protocol' => 'openid-connect',
                'publicClient' => false,
                'clientAuthenticatorType' => 'client-secret',
            ];
        } else {
            $result = $existing;
        }

        $result['redirectUris'] = $this->unionStringList(
            $result['redirectUris'] ?? [],
            $this->redirectUris
        );
        $result['webOrigins'] = $this->unionStringList(
            $result['webOrigins'] ?? [],
            $this->webOrigins
        );

        $attributes = is_array($result['attributes'] ?? null) ? $result['attributes'] : [];
        $existingPostLogout = isset($attributes['post.logout.redirect.uris'])
            ? (string)$attributes['post.logout.redirect.uris']
            : '';
        $existingPostLogoutList = $existingPostLogout === '' ? [] : explode('##', $existingPostLogout);

        $attributes['post.logout.redirect.uris'] = implode(
            '##',
            $this->unionStringList($existingPostLogoutList, $this->postLogoutRedirectUris)
        );
        $attributes['pkce.code.challenge.method'] = 'S256';
        $attributes['backchannel.logout.session.required'] = 'true';
        $attributes['backchannel.logout.revoke.offline.tokens'] = 'false';

        if ($this->backchannelLogoutUrl !== '') {
            $attributes['backchannel.logout.url'] = $this->backchannelLogoutUrl;
        }

        $result['attributes'] = $attributes;
        $result['standardFlowEnabled'] = true;
        $result['implicitFlowEnabled'] = false;
        $result['directAccessGrantsEnabled'] = false;
        $result['frontchannelLogout'] = false;

        return $result;
    }

    /**
     * Returns dotted keys whose value would change as `[old, new]` pairs.
     *
     * @return array<string, array{0: mixed, 1: mixed}>
     */
    public function diff(?array $existing): array
    {
        $new = $this->mergeInto($existing);
        $old = is_array($existing) ? $existing : [];
        $diff = [];

        $topKeys = array_keys(array_merge($old, $new));
        foreach ($topKeys as $key) {
            if ($key === 'attributes') {
                continue;
            }
            $oldValue = $old[$key] ?? null;
            $newValue = $new[$key] ?? null;
            if ($oldValue !== $newValue) {
                $diff[$key] = [$oldValue, $newValue];
            }
        }

        $oldAttributes = is_array($old['attributes'] ?? null) ? $old['attributes'] : [];
        $newAttributes = $new['attributes'] ?? [];
        $attributeKeys = array_keys(array_merge($oldAttributes, $newAttributes));
        foreach ($attributeKeys as $attributeKey) {
            $oldValue = $oldAttributes[$attributeKey] ?? null;
            $newValue = $newAttributes[$attributeKey] ?? null;
            if ($oldValue !== $newValue) {
                $diff['attributes.' . $attributeKey] = [$oldValue, $newValue];
            }
        }

        return $diff;
    }

    /**
     * @param list<string> $existing
     * @param list<string> $new
     * @return list<string>
     */
    private function unionStringList(array $existing, array $new): array
    {
        $result = [];
        foreach (array_merge($existing, $new) as $value) {
            $value = (string)$value;
            if ($value === '' || in_array($value, $result, true)) {
                continue;
            }
            $result[] = $value;
        }
        return $result;
    }
}
