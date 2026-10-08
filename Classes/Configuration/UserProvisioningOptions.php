<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Configuration;

/**
 * Provisioning rules for one user table (fe_users or be_users).
 */
final readonly class UserProvisioningOptions
{
    /**
     * @param list<int> $defaultGroups
     * @param array<string, string> $mapping column => claim
     * @param array<string, list<int>> $groupMapping claim value pattern => group uids
     */
    public function __construct(
        public string $table,
        public string $groupTable,
        public int $storagePid,
        public array $defaultGroups,
        public bool $createUsers,
        public bool $reEnableDisabled,
        public bool $undelete,
        public string $linkByField,
        public string $linkByClaim,
        public bool $linkRequireVerifiedEmail,
        public string $groupsClaim,
        public array $mapping,
        public array $groupMapping,
    ) {}
}
