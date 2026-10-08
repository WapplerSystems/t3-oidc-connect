<?php

declare(strict_types=1);

use TYPO3\CMS\Core\Cache\Backend\Typo3DatabaseBackend;
use TYPO3\CMS\Core\Cache\Frontend\VariableFrontend;
use TYPO3\CMS\Core\Utility\ExtensionManagementUtility;
use WapplerSystems\OidcConnect\Backend\OidcLoginProvider;
use WapplerSystems\OidcConnect\Service\OidcAuthenticationService;

defined('TYPO3') or die();

// Discovery documents, JWKS, in-flight authorization states and the
// back-channel logout replay guard. Must be shared between all web nodes.
$GLOBALS['TYPO3_CONF_VARS']['SYS']['caching']['cacheConfigurations']['oidc_connect'] ??= [
    'frontend' => VariableFrontend::class,
    'backend' => Typo3DatabaseBackend::class,
    'options' => ['defaultLifetime' => 3600],
    'groups' => ['system'],
];

// Acts only on requests carrying a verified OIDC identity, see the class.
ExtensionManagementUtility::addService(
    'oidc_connect',
    'auth',
    OidcAuthenticationService::class,
    [
        'title' => 'OpenID Connect authentication',
        'description' => 'Logs in frontend and backend users after a verified OpenID Connect callback.',
        'subtype' => 'getUserFE,authUserFE,getUserBE,authUserBE',
        'available' => true,
        'priority' => 85,
        'quality' => 80,
        'os' => '',
        'exec' => '',
        'className' => OidcAuthenticationService::class,
    ]
);

$GLOBALS['TYPO3_CONF_VARS']['EXTCONF']['backend']['loginProviders'][OidcLoginProvider::IDENTIFIER] = [
    'provider' => OidcLoginProvider::class,
    'sorting' => 60,
    'iconIdentifier' => 'actions-key',
    'label' => 'LLL:EXT:oidc_connect/Resources/Private/Language/locallang.xlf:backend.login.tab',
];
