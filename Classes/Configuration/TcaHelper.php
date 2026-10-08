<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Configuration;

use TYPO3\CMS\Core\Utility\ExtensionManagementUtility;

/**
 * @internal
 */
final class TcaHelper
{
    public static function addIdentityColumns(string $table): void
    {
        $ll = 'LLL:EXT:oidc_connect/Resources/Private/Language/locallang_db.xlf:';
        ExtensionManagementUtility::addTCAcolumns($table, [
            'tx_oidcconnect_issuer' => [
                'exclude' => true,
                'label' => $ll . 'users.tx_oidcconnect_issuer',
                'config' => ['type' => 'input', 'size' => 40, 'max' => 255],
            ],
            'tx_oidcconnect_subject' => [
                'exclude' => true,
                'label' => $ll . 'users.tx_oidcconnect_subject',
                'description' => $ll . 'users.tx_oidcconnect_subject.description',
                'config' => ['type' => 'input', 'size' => 40, 'max' => 255],
            ],
        ]);
        $GLOBALS['TCA'][$table]['palettes']['tx_oidcconnect'] = [
            'label' => $ll . 'users.palette',
            'showitem' => 'tx_oidcconnect_issuer, tx_oidcconnect_subject',
        ];
        ExtensionManagementUtility::addToAllTCAtypes(
            $table,
            '--div--;' . $ll . 'users.tab, --palette--;;tx_oidcconnect'
        );
    }
}
