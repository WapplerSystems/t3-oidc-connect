<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Event;

use Psr\Http\Message\ServerRequestInterface;
use TYPO3\CMS\Core\Site\Entity\Site;
use WapplerSystems\OidcConnect\Authentication\AuthorizationStateRecord;
use WapplerSystems\OidcConnect\Configuration\OidcConnectSettings;

/**
 * Dispatched right before the OIDC callback middleware calls the token
 * endpoint. Listeners may abort the flow by calling {@see abort()} —
 * typical use case: rate limiting, custom validation, IP allow-listing.
 */
final class BeforeTokenExchangeEvent
{
    private bool $aborted = false;
    private string $abortReason = '';

    public function __construct(
        public readonly ServerRequestInterface $request,
        public readonly Site $site,
        public readonly OidcConnectSettings $settings,
        public readonly AuthorizationStateRecord $state,
        public readonly string $authorizationCode,
    ) {}

    public function abort(string $reason = ''): void
    {
        $this->aborted = true;
        $this->abortReason = $reason;
    }

    public function isAborted(): bool { return $this->aborted; }
    public function abortReason(): string { return $this->abortReason; }
}
