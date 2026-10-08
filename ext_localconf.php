<?php

declare(strict_types=1);

defined('TYPO3') or die();

// Dedicated cache for OIDC discovery documents (well-known) + short-lived
// authorization-state records. Lifetime: 1 h (discovery) / per-entry TTL
// for state records that the middleware sets explicitly.
$GLOBALS['TYPO3_CONF_VARS']['SYS']['caching']['cacheConfigurations']['oidc_connect'] ??= [
    'frontend' => \TYPO3\CMS\Core\Cache\Frontend\VariableFrontend::class,
    'backend'  => \TYPO3\CMS\Core\Cache\Backend\Typo3DatabaseBackend::class,
    'options'  => ['defaultLifetime' => 3600],
    'groups'   => ['system'],
];
