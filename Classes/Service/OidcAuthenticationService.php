<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Service;

use Psr\Http\Message\ServerRequestInterface;
use TYPO3\CMS\Core\Authentication\AbstractAuthenticationService;
use TYPO3\CMS\Core\Site\Entity\Site;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use WapplerSystems\OidcConnect\Authentication\VerifiedIdentity;
use WapplerSystems\OidcConnect\Configuration\OidcConnectSettingsFactory;
use WapplerSystems\OidcConnect\User\UserProvisioner;

/**
 * Authentication service for frontend and backend.
 *
 * It only acts on requests that carry a {@see VerifiedIdentity} attribute,
 * which the callback middlewares set after the complete OIDC validation.
 * All other logins (password, other SSO services) pass through untouched.
 *
 * Going through the core authentication chain instead of creating sessions
 * by hand keeps session-id regeneration, lastlogin, rate limiting, login
 * events and MFA intact.
 */
class OidcAuthenticationService extends AbstractAuthenticationService
{
    private const OK_BREAK = 200;
    private const NOT_RESPONSIBLE = 100;
    private const MARKER = '_oidc_connect_identity';

    public function getUser(): array|false
    {
        $identity = $this->identity();
        if ($identity === null) {
            return false;
        }
        $factory = GeneralUtility::makeInstance(OidcConnectSettingsFactory::class);
        $site = $this->request()?->getAttribute('site');
        $settings = match (true) {
            $identity->loginType === 'BE' => $factory->forBackend(),
            $site instanceof Site => $factory->forSite($site),
            default => null,
        };
        if ($settings === null || $settings->siteIdentifier() !== $identity->siteIdentifier) {
            return false;
        }

        $user = GeneralUtility::makeInstance(UserProvisioner::class)
            ->provision($identity, $settings->userOptions($identity->loginType));
        if ($user === null) {
            return false;
        }
        $user[self::MARKER] = $identity->issuer . '|' . $identity->subject;
        return $user;
    }

    public function authUser(array $user): int
    {
        $identity = $this->identity();
        if ($identity === null || !isset($user[self::MARKER])) {
            return self::NOT_RESPONSIBLE;
        }
        // Only the record this service resolved for this very identity is
        // accepted; a record proposed by another service is not vouched for.
        if ($user[self::MARKER] !== $identity->issuer . '|' . $identity->subject
            || ($user['tx_oidcconnect_subject'] ?? '') !== $identity->subject
            || ($user['tx_oidcconnect_issuer'] ?? '') !== $identity->issuer
        ) {
            return -1;
        }
        return self::OK_BREAK;
    }

    private function identity(): ?VerifiedIdentity
    {
        $identity = $this->request()?->getAttribute(VerifiedIdentity::REQUEST_ATTRIBUTE);
        if (!$identity instanceof VerifiedIdentity || $identity->loginType !== ($this->authInfo['loginType'] ?? '')) {
            return null;
        }
        return $identity;
    }

    private function request(): ?ServerRequestInterface
    {
        $request = $this->authInfo['request'] ?? null;
        return $request instanceof ServerRequestInterface ? $request : null;
    }
}
