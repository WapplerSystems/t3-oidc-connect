<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Event;

use WapplerSystems\OidcConnect\Authentication\VerifiedIdentity;

/**
 * Dispatched before a user record is inserted or updated after a
 * successful OIDC login. Listeners may change the data that is written or
 * deny the login altogether.
 */
final class BeforeUserProvisionedEvent
{
    private bool $denied = false;

    /**
     * @param array<string, mixed>|null $existingRecord null when a new record is about to be created
     * @param array<string, mixed> $data columns that will be written
     */
    public function __construct(
        public readonly VerifiedIdentity $identity,
        public readonly string $table,
        public readonly ?array $existingRecord,
        private array $data,
    ) {}

    /** @return array<string, mixed> */
    public function getData(): array
    {
        return $this->data;
    }

    /** @param array<string, mixed> $data */
    public function setData(array $data): void
    {
        $this->data = $data;
    }

    public function deny(): void
    {
        $this->denied = true;
    }

    public function isDenied(): bool
    {
        return $this->denied;
    }
}
