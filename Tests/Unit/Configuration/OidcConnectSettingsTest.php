<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Tests\Unit\Configuration;

use PHPUnit\Framework\Attributes\Test;
use TYPO3\TestingFramework\Core\Unit\UnitTestCase;
use WapplerSystems\OidcConnect\Configuration\OidcConnectSettings;

final class OidcConnectSettingsTest extends UnitTestCase
{
    #[Test]
    public function scopesAlgorithmsRoutesAndConfiguredStateBehaveAsExpected(): void
    {
        $settings = new OidcConnectSettings('main', []);
        self::assertSame(['openid'], $settings->scopes());

        $settings = new OidcConnectSettings('main', [
            'auth' => ['allowedSigningAlgorithms' => ['none', 'HS256', 'RS256']],
        ]);
        self::assertSame(['RS256'], $settings->allowedSigningAlgorithms());

        self::assertSame('/oauth_callback', $settings->route('callback'));

        $settings = new OidcConnectSettings('main', [
            'routes' => ['callback' => 'foo'],
        ]);
        self::assertSame('/foo', $settings->route('callback'));

        $settings = new OidcConnectSettings('main', [
            'issuer' => 'https://idp.example',
        ]);
        self::assertFalse($settings->isConfigured());
    }

    #[Test]
    public function userOptionsForFrontendMapUsersSettingsAndGroupMappings(): void
    {
        $settings = new OidcConnectSettings('main', [
            'users' => [
                'storagePid' => 12,
                'mustExistLocally' => false,
                'reEnableDisabled' => true,
                'undelete' => true,
                'linkByField' => 'username',
                'linkByClaim' => 'email',
                'linkRequireVerifiedEmail' => false,
                'groupsClaim' => 'groups',
                'defaultGroups' => '1,2',
            ],
            'mapping' => [
                'fe_users' => ['username' => 'preferred_username'],
            ],
            'groupMapping' => [
                'fe_groups' => ['/partner*' => '3,4'],
            ],
        ]);

        $options = $settings->userOptions('FE');

        self::assertSame('fe_users', $options->table);
        self::assertSame('fe_groups', $options->groupTable);
        self::assertSame(12, $options->storagePid);
        self::assertSame([1, 2], $options->defaultGroups);
        self::assertTrue($options->createUsers);
        self::assertTrue($options->reEnableDisabled);
        self::assertTrue($options->undelete);
        self::assertSame('username', $options->linkByField);
        self::assertSame('email', $options->linkByClaim);
        self::assertFalse($options->linkRequireVerifiedEmail);
        self::assertSame('groups', $options->groupsClaim);
        self::assertSame(['username' => 'preferred_username'], $options->mapping);
        self::assertSame(['/partner*' => [3, 4]], $options->groupMapping);
    }
}
