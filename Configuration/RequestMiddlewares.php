<?php

declare(strict_types=1);

use WapplerSystems\OidcConnect\Backend\BackendLogoutMiddleware;
use WapplerSystems\OidcConnect\Backend\BackendOidcMiddleware;
use WapplerSystems\OidcConnect\Middleware\BackchannelLogoutMiddleware;
use WapplerSystems\OidcConnect\Middleware\FrontendAuthorizeMiddleware;
use WapplerSystems\OidcConnect\Middleware\FrontendCallbackMiddleware;
use WapplerSystems\OidcConnect\Middleware\FrontendLoginFinisherMiddleware;
use WapplerSystems\OidcConnect\Middleware\FrontendLogoutMiddleware;
use WapplerSystems\OidcConnect\Middleware\SessionRevocationMiddleware;
use WapplerSystems\OidcConnect\Middleware\SilentSsoMiddleware;

return [
    'frontend' => [
        // --- before frontend authentication: need the site, not the user
        'wapplersystems/oidc-connect/backchannel-logout' => [
            'target' => BackchannelLogoutMiddleware::class,
            'after' => ['typo3/cms-frontend/site'],
            'before' => ['typo3/cms-frontend/authentication'],
        ],
        'wapplersystems/oidc-connect/authorize' => [
            'target' => FrontendAuthorizeMiddleware::class,
            'after' => ['typo3/cms-frontend/site'],
            'before' => ['typo3/cms-frontend/authentication'],
        ],
        'wapplersystems/oidc-connect/callback' => [
            'target' => FrontendCallbackMiddleware::class,
            'after' => ['typo3/cms-frontend/site', 'wapplersystems/oidc-connect/authorize'],
            // causal/oidc (when still installed during a migration) answers
            // every request carrying ?code= with 400, so run before it.
            'before' => ['typo3/cms-frontend/authentication', 'oidccallback'],
        ],
        // --- after frontend authentication: need the user
        'wapplersystems/oidc-connect/session-revocation' => [
            'target' => SessionRevocationMiddleware::class,
            'after' => ['typo3/cms-frontend/authentication'],
            'before' => ['typo3/cms-frontend/base-redirect-resolver'],
        ],
        'wapplersystems/oidc-connect/login-finisher' => [
            'target' => FrontendLoginFinisherMiddleware::class,
            'after' => ['wapplersystems/oidc-connect/session-revocation'],
            'before' => ['typo3/cms-frontend/base-redirect-resolver'],
        ],
        'wapplersystems/oidc-connect/logout' => [
            'target' => FrontendLogoutMiddleware::class,
            'after' => ['wapplersystems/oidc-connect/login-finisher'],
            'before' => ['typo3/cms-frontend/base-redirect-resolver'],
        ],
        'wapplersystems/oidc-connect/silent-sso' => [
            'target' => SilentSsoMiddleware::class,
            'after' => ['wapplersystems/oidc-connect/logout'],
            'before' => ['typo3/cms-frontend/base-redirect-resolver'],
        ],
    ],
    'backend' => [
        'wapplersystems/oidc-connect/backend' => [
            'target' => BackendOidcMiddleware::class,
            'after' => ['typo3/cms-backend/backend-routing'],
            'before' => ['typo3/cms-backend/authentication'],
        ],
        'wapplersystems/oidc-connect/backend-session-revocation' => [
            'target' => SessionRevocationMiddleware::class,
            'after' => ['typo3/cms-backend/authentication'],
        ],
        'wapplersystems/oidc-connect/backend-logout' => [
            'target' => BackendLogoutMiddleware::class,
            'after' => ['typo3/cms-backend/authentication'],
        ],
    ],
];
