<?php

declare(strict_types=1);

return [
    'oidc_connect_callback' => [
        'path' => '/oidc-connect/callback',
        'access' => 'public',
        'target' => \WapplerSystems\OidcConnect\Backend\CallbackController::class,
    ],
];
