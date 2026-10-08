<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Event;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use TYPO3\CMS\Core\Site\Entity\Site;
use WapplerSystems\OidcConnect\Authentication\AuthorizationStateRecord;
use WapplerSystems\OidcConnect\Authentication\TokenSet;
use WapplerSystems\OidcConnect\Configuration\OidcConnectSettings;

/**
 * Dispatched once the IdP has returned a valid token set. THIS is the
 * hook where user resolution / fe_users session creation belongs:
 * a listener (next milestone) consumes the tokens, calls userinfo,
 * looks up or creates an fe_users row, logs the user in, and replaces
 * the default redirect via {@see overrideResponse()} if a different
 * response is required (e.g. an interim 2FA challenge page).
 */
final class AfterTokenExchangedEvent
{
    private ?ResponseInterface $overrideResponse = null;

    public function __construct(
        public readonly ServerRequestInterface $request,
        public readonly Site $site,
        public readonly OidcConnectSettings $settings,
        public readonly AuthorizationStateRecord $state,
        public readonly TokenSet $tokens,
    ) {}

    public function overrideResponse(ResponseInterface $response): void
    {
        $this->overrideResponse = $response;
    }

    public function getOverrideResponse(): ?ResponseInterface
    {
        return $this->overrideResponse;
    }
}
