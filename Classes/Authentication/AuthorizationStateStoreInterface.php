<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Authentication;

/**
 * Short-lived persistence for in-flight OIDC authorization requests.
 *
 * Lifecycle:
 *   - Authorization middleware: {@see save()} the record before redirecting
 *     the user to the IdP authorize endpoint.
 *   - Callback middleware: {@see consume()} the record using the `state`
 *     URL parameter. Returns null if missing, expired, or already
 *     consumed; the record is removed atomically on a successful read.
 *   - Aborted flow / errors: {@see discard()} drops the record.
 *
 * Implementations MUST guarantee single-use semantics for {@see consume()}.
 */
interface AuthorizationStateStoreInterface
{
    public function save(AuthorizationStateRecord $record, int $ttl = 600): void;

    public function consume(string $state): ?AuthorizationStateRecord;

    public function discard(string $state): void;
}
