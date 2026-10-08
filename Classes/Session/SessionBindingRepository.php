<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Session;

use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use WapplerSystems\OidcConnect\Authentication\VerifiedIdentity;

/**
 * Links TYPO3 sessions to the provider session they came from.
 *
 * The binding uid is stored in the TYPO3 session data; the session id
 * itself is never written here. Back-channel logout marks bindings as
 * revoked, and {@see \WapplerSystems\OidcConnect\Middleware\SessionRevocationMiddleware}
 * ends the TYPO3 session on its next request. That works for every
 * session backend (database, Redis, ...).
 */
final class SessionBindingRepository
{
    public const TABLE = 'tx_oidcconnect_session';
    public const SESSION_DATA_KEY = 'oidc_connect';
    private const MAX_AGE = 90 * 86400;

    public function __construct(
        private readonly ConnectionPool $connectionPool,
    ) {}

    public function create(VerifiedIdentity $identity, int $userUid): int
    {
        $connection = $this->connection();
        $connection->insert(self::TABLE, [
            'login_type' => $identity->loginType,
            'site' => $identity->siteIdentifier,
            'user_uid' => $userUid,
            'issuer' => $identity->issuer,
            'subject' => $identity->subject,
            'sid' => $identity->sessionId,
            'id_token' => $identity->idToken,
            'crdate' => time(),
            'revoked' => 0,
        ]);
        $uid = (int)$connection->lastInsertId();
        if (random_int(1, 100) === 1) {
            $this->collectGarbage();
        }
        return $uid;
    }

    /** @return array<string, mixed>|null */
    public function find(int $uid): ?array
    {
        if ($uid <= 0) {
            return null;
        }
        $row = $this->connection()->select(['*'], self::TABLE, ['uid' => $uid])->fetchAssociative();
        return is_array($row) ? $row : null;
    }

    public function isRevoked(int $uid): bool
    {
        $row = $this->connection()->select(['revoked'], self::TABLE, ['uid' => $uid])->fetchAssociative();
        // A binding that vanished (garbage collection) is not a revocation.
        return is_array($row) && (int)$row['revoked'] > 0;
    }

    public function revoke(int $uid): void
    {
        $this->connection()->update(self::TABLE, ['revoked' => time(), 'id_token' => ''], ['uid' => $uid]);
    }

    /**
     * Revokes all bindings of a provider session (`sid`) or, without sid,
     * of a subject. Returns the number of revoked bindings.
     */
    public function revokeByProviderSession(string $issuer, string $sid, string $subject): int
    {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable(self::TABLE);
        $queryBuilder
            ->update(self::TABLE)
            ->set('revoked', time())
            ->set('id_token', '')
            ->where(
                $queryBuilder->expr()->eq('issuer', $queryBuilder->createNamedParameter($issuer)),
                $queryBuilder->expr()->eq('revoked', $queryBuilder->createNamedParameter(0, Connection::PARAM_INT)),
            );
        if ($sid !== '') {
            $queryBuilder->andWhere($queryBuilder->expr()->eq('sid', $queryBuilder->createNamedParameter($sid)));
            if ($subject !== '') {
                $queryBuilder->andWhere($queryBuilder->expr()->eq('subject', $queryBuilder->createNamedParameter($subject)));
            }
        } elseif ($subject !== '') {
            $queryBuilder->andWhere($queryBuilder->expr()->eq('subject', $queryBuilder->createNamedParameter($subject)));
        } else {
            return 0;
        }
        return (int)$queryBuilder->executeStatement();
    }

    public function collectGarbage(): void
    {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable(self::TABLE);
        $queryBuilder
            ->delete(self::TABLE)
            ->where($queryBuilder->expr()->lt('crdate', $queryBuilder->createNamedParameter(time() - self::MAX_AGE, Connection::PARAM_INT)))
            ->executeStatement();
    }

    private function connection(): Connection
    {
        return $this->connectionPool->getConnectionForTable(self::TABLE);
    }
}
