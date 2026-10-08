<?php

declare(strict_types=1);

return [
    'frontend' => [
        // Catches `/oidcConnect.authorizeRoute` (default `/oauth_authorize`)
        // and redirects to the IdP authorize endpoint. Must run after site
        // resolution (needs `site` + `language` attributes on the request)
        // but before frontend user authentication so the redirect happens
        // before TYPO3 attempts to log the (anonymous) user in.
        'wapplersystems/oidc-connect/authorize' => [
            'target' => \WapplerSystems\OidcConnect\Middleware\AuthorizationRequestMiddleware::class,
            'after'  => [
                'typo3/cms-frontend/site',
            ],
            'before' => [
                'typo3/cms-frontend/authentication',
            ],
        ],

        // Catches `oidcConnect.callbackRoute` (default `/oauth_callback`).
        // Must run after site resolution (needs the `site` attribute and
        // settings) and before authentication so the redirect or fe_users
        // session created by the AfterTokenExchangedEvent listener takes
        // effect for the next request.
        'wapplersystems/oidc-connect/callback' => [
            'target' => \WapplerSystems\OidcConnect\Middleware\OauthCallbackMiddleware::class,
            'after'  => [
                'typo3/cms-frontend/site',
            ],
            'before' => [
                'typo3/cms-frontend/authentication',
            ],
        ],
    ],
];
