<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\User;

use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use TYPO3\CMS\Core\Crypto\PasswordHashing\PasswordHashFactory;
use TYPO3\CMS\Core\Crypto\Random;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use WapplerSystems\OidcConnect\Authentication\VerifiedIdentity;
use WapplerSystems\OidcConnect\Configuration\UserProvisioningOptions;
use WapplerSystems\OidcConnect\Event\BeforeUserProvisionedEvent;

/**
 * Finds, links, creates and updates the local user record for a verified
 * identity.
 *
 * Lookup order:
 *   1. issuer + subject (an account that already logged in via OIDC)
 *   2. `linkByField` = claim `linkByClaim`, only among accounts that are not
 *      yet linked, only if unambiguous and, for e-mail claims, only if the
 *      provider says the address is verified (account takeover guard)
 *   3. create a new record, if allowed
 */
final class UserProvisioner implements LoggerAwareInterface
{
    use LoggerAwareTrait;

    /** Columns that mapping must never write. */
    private const PROTECTED_COLUMNS = [
        'uid', 'pid', 'deleted', 'disable', 'starttime', 'endtime', 'password', 'usergroup',
        'admin', 'options', 'workspace_perms', 'file_permissions', 'db_mountpoints', 'file_mountpoints',
        'tstamp', 'crdate', 'lastlogin', 'mfa', 'tx_oidcconnect_issuer', 'tx_oidcconnect_subject',
    ];

    public function __construct(
        private readonly ConnectionPool $connectionPool,
        private readonly EventDispatcherInterface $eventDispatcher,
        private readonly PasswordHashFactory $passwordHashFactory,
        private readonly Random $random,
    ) {}

    /**
     * @return array<string, mixed>|null the user record, null if access is denied
     */
    public function provision(VerifiedIdentity $identity, UserProvisioningOptions $options): ?array
    {
        $table = $options->table;
        $existing = $this->findLinked($identity, $options) ?? $this->findLinkable($identity, $options);

        if ($existing !== null && !$this->isAllowed($existing, $options)) {
            return null;
        }
        if ($existing === null && !$options->createUsers) {
            $this->logger?->info('oidc-connect: no local {table} record for {sub}, creation disabled', ['table' => $table, 'sub' => $identity->subject]);
            return null;
        }
        if ($existing === null && $table === 'fe_users' && $options->storagePid <= 0) {
            $this->logger?->error('oidc-connect: cannot create fe_users record, oidcConnect.users.storagePid is not set');
            return null;
        }

        $data = $this->mapClaims($identity, $options, $existing);
        $data['tx_oidcconnect_issuer'] = $identity->issuer;
        $data['tx_oidcconnect_subject'] = $identity->subject;
        if ($existing !== null) {
            $data['deleted'] = 0;
            $data['disable'] = 0;
        }

        $groups = $this->resolveGroups($identity, $options, $existing);
        if ($groups !== null) {
            $data['usergroup'] = implode(',', $groups);
        }

        if ($existing === null) {
            if (($data['usergroup'] ?? '') === '' && $table === 'fe_users') {
                $this->logger?->info('oidc-connect: new frontend user {sub} would have no group, denied', ['sub' => $identity->subject]);
                return null;
            }
            $data += [
                'pid' => $table === 'fe_users' ? $options->storagePid : 0,
                'username' => $this->uniqueUsername($this->proposedUsername($identity, $data), $options),
                'password' => $this->randomPasswordHash($table === 'fe_users' ? 'FE' : 'BE'),
                'crdate' => time(),
            ];
        }

        $event = new BeforeUserProvisionedEvent($identity, $table, $existing, $data);
        $this->eventDispatcher->dispatch($event);
        if ($event->isDenied()) {
            $this->logger?->info('oidc-connect: provisioning of {sub} denied by event listener', ['sub' => $identity->subject]);
            return null;
        }
        $data = $event->getData();

        $connection = $this->connectionPool->getConnectionForTable($table);
        if ($existing === null) {
            $data['tstamp'] = time();
            $connection->insert($table, $data);
            $uid = (int)$connection->lastInsertId();
            $this->logger?->info('oidc-connect: created {table} record {uid} for {sub}', ['table' => $table, 'uid' => $uid, 'sub' => $identity->subject]);
        } else {
            $uid = (int)$existing['uid'];
            $changes = array_filter(
                $data,
                static fn(mixed $value, string $column): bool => !array_key_exists($column, $existing) || (string)$existing[$column] !== (string)$value,
                ARRAY_FILTER_USE_BOTH
            );
            if ($changes !== []) {
                $changes['tstamp'] = time();
                $connection->update($table, $changes, ['uid' => $uid]);
            }
        }

        $row = $connection->select(['*'], $table, ['uid' => $uid])->fetchAssociative();
        return is_array($row) ? $row : null;
    }

    /** @return array<string, mixed>|null */
    private function findLinked(VerifiedIdentity $identity, UserProvisioningOptions $options): ?array
    {
        $queryBuilder = $this->queryBuilder($options);
        $queryBuilder->where(
            $queryBuilder->expr()->eq('tx_oidcconnect_subject', $queryBuilder->createNamedParameter($identity->subject)),
            $queryBuilder->expr()->eq('tx_oidcconnect_issuer', $queryBuilder->createNamedParameter($identity->issuer)),
        );
        $this->restrictToStorage($queryBuilder, $options);
        $rows = $queryBuilder->orderBy('deleted')->addOrderBy('disable')->addOrderBy('uid')->executeQuery()->fetchAllAssociative();
        if (count($rows) > 1) {
            $this->logger?->warning('oidc-connect: {count} {table} records linked to {sub}, using uid {uid}', [
                'count' => count($rows), 'table' => $options->table, 'sub' => $identity->subject, 'uid' => $rows[0]['uid'],
            ]);
        }
        return $rows[0] ?? null;
    }

    /** @return array<string, mixed>|null */
    private function findLinkable(VerifiedIdentity $identity, UserProvisioningOptions $options): ?array
    {
        if (!in_array($options->linkByField, ['username', 'email'], true) || $options->linkByClaim === '') {
            return null;
        }
        $value = $identity->claim($options->linkByClaim);
        if (!is_scalar($value) || trim((string)$value) === '') {
            return null;
        }
        $isEmailClaim = $options->linkByClaim === 'email' || $options->linkByField === 'email';
        if ($isEmailClaim && $options->linkRequireVerifiedEmail && $identity->claim('email_verified') !== true) {
            $this->logger?->notice('oidc-connect: not linking {sub} by e-mail, address is not verified', ['sub' => $identity->subject]);
            return null;
        }

        $queryBuilder = $this->queryBuilder($options);
        $queryBuilder->where(
            $queryBuilder->expr()->eq($options->linkByField, $queryBuilder->createNamedParameter(trim((string)$value))),
            $queryBuilder->expr()->eq('tx_oidcconnect_subject', $queryBuilder->createNamedParameter('')),
            $queryBuilder->expr()->eq('deleted', $queryBuilder->createNamedParameter(0, Connection::PARAM_INT)),
        );
        $this->restrictToStorage($queryBuilder, $options);
        $rows = $queryBuilder->setMaxResults(2)->executeQuery()->fetchAllAssociative();
        if (count($rows) > 1) {
            $this->logger?->error('oidc-connect: ambiguous {field} match for {sub}, refusing to link', ['field' => $options->linkByField, 'sub' => $identity->subject]);
            return null;
        }
        if ($rows !== []) {
            $this->logger?->info('oidc-connect: linking {table} record {uid} to {sub}', ['table' => $options->table, 'uid' => $rows[0]['uid'], 'sub' => $identity->subject]);
        }
        return $rows[0] ?? null;
    }

    /** @param array<string, mixed> $row */
    private function isAllowed(array $row, UserProvisioningOptions $options): bool
    {
        if ((int)$row['deleted'] === 1 && !$options->undelete) {
            $this->logger?->info('oidc-connect: {table} record {uid} is deleted, access denied', ['table' => $options->table, 'uid' => $row['uid']]);
            return false;
        }
        if ((int)$row['disable'] === 1 && !$options->reEnableDisabled) {
            $this->logger?->info('oidc-connect: {table} record {uid} is disabled, access denied', ['table' => $options->table, 'uid' => $row['uid']]);
            return false;
        }
        $now = time();
        if ((int)($row['starttime'] ?? 0) > $now || ((int)($row['endtime'] ?? 0) > 0 && (int)$row['endtime'] < $now)) {
            $this->logger?->info('oidc-connect: {table} record {uid} is outside its start/end time', ['table' => $options->table, 'uid' => $row['uid']]);
            return false;
        }
        return true;
    }

    /**
     * @param array<string, mixed>|null $existing
     * @return array<string, string>
     */
    private function mapClaims(VerifiedIdentity $identity, UserProvisioningOptions $options, ?array $existing): array
    {
        $columns = $GLOBALS['TCA'][$options->table]['columns'] ?? [];
        $data = [];
        foreach ($options->mapping as $column => $source) {
            if (in_array($column, self::PROTECTED_COLUMNS, true) || (!isset($columns[$column]) && $column !== 'username')) {
                $this->logger?->warning('oidc-connect: mapping to {table}.{column} is not allowed', ['table' => $options->table, 'column' => $column]);
                continue;
            }
            if ($column === 'username' && $existing !== null) {
                continue; // never rename an existing account
            }
            if (str_starts_with($source, '=')) {
                $data[$column] = substr($source, 1);
                continue;
            }
            $value = $identity->claim($source);
            if (is_array($value)) {
                $value = implode(', ', array_filter(array_map(static fn($v): string => is_scalar($v) ? (string)$v : '', $value)));
            }
            if ($value === null || !is_scalar($value)) {
                continue; // a missing claim keeps the current value
            }
            $data[$column] = (string)$value;
        }
        return $data;
    }

    /**
     * New group list, or null to leave the record's groups untouched.
     *
     * @param array<string, mixed>|null $existing
     * @return list<int>|null
     */
    private function resolveGroups(VerifiedIdentity $identity, UserProvisioningOptions $options, ?array $existing): ?array
    {
        $managed = [];
        foreach ($options->groupMapping as $uids) {
            array_push($managed, ...$uids);
        }
        if ($managed === [] && $options->defaultGroups === [] && $existing !== null) {
            return null;
        }

        $current = $existing !== null
            ? array_map('intval', array_filter(explode(',', (string)$existing['usergroup'])))
            : [];
        $groups = array_diff($current, $managed);

        if ($options->groupsClaim !== '' && $options->groupMapping !== []) {
            $values = $identity->claim($options->groupsClaim);
            $values = is_array($values) ? $values : ($values === null ? [] : [$values]);
            foreach ($values as $value) {
                if (!is_scalar($value)) {
                    continue;
                }
                foreach ($options->groupMapping as $pattern => $uids) {
                    if (self::matches((string)$pattern, (string)$value)) {
                        array_push($groups, ...$uids);
                    }
                }
            }
        }
        array_push($groups, ...$options->defaultGroups);

        return array_values(array_unique(array_filter($groups, static fn(int $uid): bool => $uid > 0)));
    }

    public static function matches(string $pattern, string $value): bool
    {
        $regex = '/^' . str_replace('\\*', '.*', preg_quote($pattern, '/')) . '$/i';
        return preg_match($regex, $value) === 1;
    }

    /** @param array<string, string> $data */
    private function proposedUsername(VerifiedIdentity $identity, array $data): string
    {
        foreach ([$data['username'] ?? null, $identity->claim('preferred_username'), $identity->claim('email'), $identity->subject] as $candidate) {
            if (is_scalar($candidate) && trim((string)$candidate) !== '') {
                return mb_substr(trim((string)$candidate), 0, 255);
            }
        }
        return $identity->subject;
    }

    private function uniqueUsername(string $username, UserProvisioningOptions $options): string
    {
        $queryBuilder = $this->queryBuilder($options);
        $queryBuilder->count('uid')->where($queryBuilder->expr()->eq('username', $queryBuilder->createNamedParameter($username)));
        if ($options->table === 'fe_users') {
            $queryBuilder->andWhere($queryBuilder->expr()->eq('pid', $queryBuilder->createNamedParameter($options->storagePid, Connection::PARAM_INT)));
        }
        if ((int)$queryBuilder->executeQuery()->fetchOne() === 0) {
            return $username;
        }
        // Taken by an unlinked account: never hijack it, fall back to a stable unique name.
        return 'oidc_' . substr(hash('sha256', $username . '|' . microtime()), 0, 16);
    }

    private function randomPasswordHash(string $mode): string
    {
        return $this->passwordHashFactory->getDefaultHashInstance($mode)->getHashedPassword($this->random->generateRandomHexString(48));
    }

    private function queryBuilder(UserProvisioningOptions $options): QueryBuilder
    {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable($options->table);
        $queryBuilder->getRestrictions()->removeAll();
        return $queryBuilder->select('*')->from($options->table);
    }

    private function restrictToStorage(QueryBuilder $queryBuilder, UserProvisioningOptions $options): void
    {
        if ($options->table === 'fe_users' && $options->storagePid > 0) {
            $queryBuilder->andWhere($queryBuilder->expr()->eq('pid', $queryBuilder->createNamedParameter($options->storagePid, Connection::PARAM_INT)));
        }
    }
}
