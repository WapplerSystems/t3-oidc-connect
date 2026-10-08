<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Authentication;

/**
 * A callback that must not log anybody in. `$reason` is a short machine
 * code that is safe to show in URLs; details go to the log only.
 */
final class CallbackException extends \RuntimeException
{
    public function __construct(
        public readonly string $reason,
        string $detail,
        public readonly ?AuthorizationStateRecord $record = null,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($detail, 1747800000, $previous);
    }

    /**
     * True for the expected outcome of a silent (prompt=none) check of a
     * visitor without a provider session.
     */
    public function isSilentFailure(): bool
    {
        return $this->record?->silent === true && $this->reason === 'login_required';
    }
}
