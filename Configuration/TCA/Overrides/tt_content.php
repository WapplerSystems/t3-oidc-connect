<?php

declare(strict_types=1);

use TYPO3\CMS\Core\Utility\ExtensionManagementUtility;

defined('TYPO3') or die();

ExtensionManagementUtility::addTcaSelectItem('tt_content', 'CType', [
    'label' => 'LLL:EXT:oidc_connect/Resources/Private/Language/locallang_db.xlf:ce.loginbutton.title',
    'description' => 'LLL:EXT:oidc_connect/Resources/Private/Language/locallang_db.xlf:ce.loginbutton.description',
    'value' => 'oidcconnect_loginbutton',
    'icon' => 'oidc-connect-login',
    'group' => 'special',
]);
$GLOBALS['TCA']['tt_content']['ctrl']['typeicon_classes']['oidcconnect_loginbutton'] = 'oidc-connect-login';
$GLOBALS['TCA']['tt_content']['types']['oidcconnect_loginbutton'] = [
    'showitem' => '
        --div--;LLL:EXT:core/Resources/Private/Language/Form/locallang_tabs.xlf:general,
            --palette--;;general,
            --palette--;;headers,
        --div--;LLL:EXT:core/Resources/Private/Language/Form/locallang_tabs.xlf:appearance,
            --palette--;;frames,
        --div--;LLL:EXT:core/Resources/Private/Language/Form/locallang_tabs.xlf:access,
            --palette--;;hidden,
            --palette--;;access,
    ',
];
