<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use TYPO3\CMS\Core\Exception\SiteNotFoundException;
use TYPO3\CMS\Core\Site\Entity\Site;
use TYPO3\CMS\Core\Site\SiteFinder;
use WapplerSystems\OidcConnect\Backend\BackendUrls;
use WapplerSystems\OidcConnect\Configuration\OidcConnectSettingsFactory;
use WapplerSystems\OidcConnect\Configuration\SecretResolver;
use WapplerSystems\OidcConnect\Discovery\ProviderMetadataResolver;
use WapplerSystems\OidcConnect\Discovery\WellKnownClient;
use WapplerSystems\OidcConnect\Http\SiteUrls;
use WapplerSystems\OidcConnect\Token\JwksProvider;

#[AsCommand(name: 'oidc:check', description: 'Check the OpenID Connect configuration of one or all sites')]
final class CheckCommand extends Command
{
    public function __construct(
        private readonly SiteFinder $siteFinder,
        private readonly OidcConnectSettingsFactory $settingsFactory,
        private readonly ProviderMetadataResolver $metadataResolver,
        private readonly JwksProvider $jwksProvider,
        private readonly WellKnownClient $wellKnownClient,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addArgument('site', InputArgument::OPTIONAL, 'Site identifier; default: all sites with an oidcConnect.clientId');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $identifier = (string)$input->getArgument('site');
        try {
            $sites = $identifier !== '' ? [$this->siteFinder->getSiteByIdentifier($identifier)] : $this->siteFinder->getAllSites();
        } catch (SiteNotFoundException) {
            $io->error(sprintf('Site "%s" not found.', $identifier));
            return Command::FAILURE;
        }

        $failed = false;
        $checked = 0;
        foreach ($sites as $site) {
            if ($identifier === '' && $this->settingsFactory->forSite($site)->clientId() === '') {
                continue;
            }
            $checked++;
            $failed = !$this->checkSite($site, $io) || $failed;
        }
        if ($checked === 0) {
            $io->warning('No site has oidcConnect.clientId configured.');
        }
        return $failed ? Command::FAILURE : Command::SUCCESS;
    }

    private function checkSite(Site $site, SymfonyStyle $io): bool
    {
        $settings = $this->settingsFactory->forSite($site);
        $errors = [];
        $warnings = [];
        $envName = $settings->clientSecretEnv() ?: SecretResolver::conventionalEnvName($site->getIdentifier());
        $origin = BackendUrls::origin($site->getBase());

        $rows = [
            ['Issuer', $settings->issuer() ?: '-'],
            ['Client ID', $settings->clientId() ?: '-'],
            ['Client secret', ($settings->clientSecret() !== '' ? 'resolved' : 'not set (public client?)') . ' — env ' . $envName],
            ['Frontend login', $settings->isFrontendEnabled() ? 'enabled' : 'disabled'],
            ['Backend login', $settings->isBackendEnabled() ? 'enabled' : 'disabled'],
            ['Redirect URI (FE)', SiteUrls::routeUrl($site, $settings->route('callback'))],
        ];
        if ($settings->isBackendEnabled()) {
            $rows[] = ['Redirect URI (BE)', BackendUrls::callbackUrl($origin)];
        }
        $rows[] = ['Back-channel logout', $settings->isBackchannelLogoutEnabled() ? SiteUrls::routeUrl($site, $settings->route('backchannelLogout')) : 'disabled'];

        if ($settings->clientId() === '') {
            $errors[] = 'oidcConnect.clientId is empty.';
        }
        if ($settings->issuer() !== '') {
            $this->wellKnownClient->forget($settings->issuer());
        }
        try {
            $metadata = $this->metadataResolver->resolve($settings);
            $rows[] = ['Discovery', 'ok, issuer matches'];
            $rows[] = ['Authorization endpoint', $metadata->authorizationEndpoint];
            $rows[] = ['Token endpoint', $metadata->tokenEndpoint];
            $rows[] = ['Userinfo endpoint', $metadata->userinfoEndpoint ?: '-'];
            $rows[] = ['End session endpoint', $metadata->endSessionEndpoint ?: '-'];
            $rows[] = ['JWKS', $metadata->jwksUri ?: '-'];
            $rows[] = ['iss parameter (RFC 9207)', $metadata->issParameterSupported ? 'supported' : 'not announced'];
            if ($metadata->endSessionEndpoint === '') {
                $warnings[] = 'Provider has no end_session_endpoint: logout only ends the TYPO3 session.';
            }
            try {
                $keys = $this->jwksProvider->keysFor($metadata->jwksUri, null, $settings->allowedSigningAlgorithms());
                $rows[] = ['Signing keys', (string)count($keys)];
                if ($keys === []) {
                    $errors[] = 'JWKS contains no signing key with an allowed algorithm.';
                }
            } catch (\Throwable $e) {
                $errors[] = 'JWKS: ' . $e->getMessage();
            }
        } catch (\Throwable $e) {
            $errors[] = 'Discovery: ' . $e->getMessage();
        }

        $options = $settings->userOptions('FE');
        if ($settings->isFrontendEnabled() && $options->createUsers && $options->storagePid <= 0) {
            $warnings[] = 'oidcConnect.users.storagePid is not set: new frontend users cannot be created.';
        }
        if ($settings->isFrontendEnabled() && $options->createUsers && $options->defaultGroups === [] && $options->groupMapping === []) {
            $warnings[] = 'Neither users.defaultGroups nor a group mapping is set: new frontend users are refused.';
        }

        $io->section('Site ' . $site->getIdentifier());
        $io->table(['Check', 'Value'], $rows);
        foreach ($warnings as $warning) {
            $io->warning($warning);
        }
        foreach ($errors as $error) {
            $io->error($error);
        }
        return $errors === [];
    }
}
