<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use TYPO3\CMS\Core\Exception\SiteNotFoundException;
use TYPO3\CMS\Core\Site\SiteFinder;
use WapplerSystems\OidcConnect\Configuration\OidcConnectSettingsFactory;
use WapplerSystems\OidcConnect\Configuration\SecretResolver;
use WapplerSystems\OidcConnect\Provisioning\ClientProvisioningPlan;
use WapplerSystems\OidcConnect\Provisioning\KeycloakAdminClient;

#[AsCommand(name: 'oidc:provision', description: 'Provision the OIDC client in Keycloak from site settings')]
final class ProvisionCommand extends Command
{
    public function __construct(
        private readonly SiteFinder $siteFinder,
        private readonly OidcConnectSettingsFactory $settingsFactory,
        private readonly KeycloakAdminClient $keycloakAdminClient,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addArgument('site', InputArgument::REQUIRED, 'Site identifier to provision')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Show changes without sending them to Keycloak')
            ->addOption('show-secret', null, InputOption::VALUE_NONE, 'Print a newly generated client secret')
            ->addOption('admin-client-id', null, InputOption::VALUE_REQUIRED, 'Keycloak admin client id (default env OIDC_CONNECT_PROVISION_CLIENT_ID)')
            ->addOption('admin-client-secret', null, InputOption::VALUE_REQUIRED, 'Keycloak admin client secret (default env OIDC_CONNECT_PROVISION_CLIENT_SECRET)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $siteIdentifier = (string)$input->getArgument('site');

        try {
            $site = $this->siteFinder->getSiteByIdentifier($siteIdentifier);
        } catch (SiteNotFoundException $e) {
            $io->error(sprintf('Site "%s" was not found.', $siteIdentifier));
            return Command::FAILURE;
        }

        $settings = $this->settingsFactory->forSite($site);
        if ($settings->issuer() === '' || $settings->clientId() === '') {
            $io->error(sprintf('Site "%s" is missing oidcConnect.issuer or oidcConnect.clientId.', $siteIdentifier));
            return Command::FAILURE;
        }

        $adminClientId = $input->getOption('admin-client-id');
        $adminClientSecret = $input->getOption('admin-client-secret');
        if (!is_string($adminClientId) || $adminClientId === '') {
            $adminClientId = self::env('OIDC_CONNECT_PROVISION_CLIENT_ID');
        }
        if (!is_string($adminClientSecret) || $adminClientSecret === '') {
            $adminClientSecret = self::env('OIDC_CONNECT_PROVISION_CLIENT_SECRET');
        }

        if ($adminClientId === '' || $adminClientSecret === '') {
            $io->error('Missing Keycloak admin credentials. Provide --admin-client-id and --admin-client-secret or set OIDC_CONNECT_PROVISION_CLIENT_ID / OIDC_CONNECT_PROVISION_CLIENT_SECRET.');
            return Command::FAILURE;
        }

        try {
            $this->keycloakAdminClient->authenticate($settings->issuer(), $adminClientId, $adminClientSecret);
            $existing = $this->keycloakAdminClient->findClient($settings->clientId());
        } catch (\RuntimeException $e) {
            $io->error($e->getMessage());
            return Command::FAILURE;
        }

        $plan = ClientProvisioningPlan::forSettings($settings, $site);
        $diff = $plan->diff($existing);

        if ($diff === []) {
            $io->success('Client is already up to date.');
            return Command::SUCCESS;
        }

        $rows = [];
        foreach ($diff as $key => [$old, $new]) {
            $rows[] = [
                $key,
                $this->formatValue($old),
                $this->formatValue($new),
            ];
        }
        $io->table(['Setting', 'Old', 'New'], $rows);

        if ($input->getOption('dry-run')) {
            $io->note('Dry run: no changes were sent to Keycloak.');
            return Command::SUCCESS;
        }

        $representation = $plan->mergeInto($existing);

        try {
            if ($existing === null) {
                $id = $this->keycloakAdminClient->createClient($representation);
                $secret = $this->keycloakAdminClient->getClientSecret($id);
                $envName = $settings->clientSecretEnv() !== ''
                    ? $settings->clientSecretEnv()
                    : SecretResolver::conventionalEnvName($site->getIdentifier());

                $io->success('Client created in Keycloak.');
                $io->text('Store the client secret in the environment variable: ' . $envName);
                if ($input->getOption('show-secret')) {
                    $io->text('Client secret: ' . $secret);
                } else {
                    $io->text('Secret value hidden. Rerun with --show-secret to print it or copy it from the Keycloak admin console.');
                }
            } else {
                $id = isset($existing['id']) && is_string($existing['id']) ? $existing['id'] : '';
                if ($id === '') {
                    throw new \RuntimeException('Existing client representation does not contain an id. Cannot update.');
                }

                $this->keycloakAdminClient->updateClient($id, $representation);
                $envName = $settings->clientSecretEnv() !== ''
                    ? $settings->clientSecretEnv()
                    : SecretResolver::conventionalEnvName($site->getIdentifier());

                $io->success('Client updated in Keycloak.');
                if ($settings->clientSecret() === '') {
                    $io->text('Locally resolved client secret is empty. Set the environment variable: ' . $envName);
                } else {
                    $io->text('Locally resolved client secret is already set.');
                }
            }
        } catch (\RuntimeException $e) {
            $io->error($e->getMessage());
            return Command::FAILURE;
        }

        return Command::SUCCESS;
    }

    private static function env(string $name): string
    {
        $value = $_ENV[$name] ?? $_SERVER[$name] ?? getenv($name);
        return is_string($value) ? $value : '';
    }

    private function formatValue(mixed $value): string
    {
        if ($value === null) {
            return '[not set]';
        }
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if (is_scalar($value)) {
            return (string)$value;
        }
        $encoded = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        return $encoded === false ? '[unprintable]' : $encoded;
    }
}
