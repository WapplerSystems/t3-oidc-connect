<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Token;

use Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use TYPO3\CMS\Core\Http\RequestFactory;
use WapplerSystems\OidcConnect\Configuration\OidcConnectSettings;
use WapplerSystems\OidcConnect\Discovery\ProviderMetadata;

/**
 * Server-to-server calls to the provider: code exchange (RFC 6749 §4.1.3),
 * and userinfo (OIDC Core §5.3).
 *
 * Uses TYPO3's RequestFactory::request(), which builds Guzzle's own PSR-7
 * request; this avoids the strict-string header problem of TYPO3's Message
 * class with Guzzle's integer Content-Length.
 */
final class TokenEndpointClient implements LoggerAwareInterface
{
    use LoggerAwareTrait;

    public function __construct(
        private readonly RequestFactory $requestFactory,
    ) {}

    /**
     * @throws TokenExchangeException
     */
    public function exchangeCode(
        OidcConnectSettings $settings,
        ProviderMetadata $metadata,
        string $code,
        string $redirectUri,
        string $codeVerifier,
    ): TokenSet {
        if ($code === '' || $redirectUri === '' || $codeVerifier === '') {
            throw new TokenExchangeException('Code, redirect_uri and code_verifier are required.', 1747500000);
        }
        $response = $this->post($metadata->tokenEndpoint, [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'code_verifier' => $codeVerifier,
        ], $settings, $metadata);

        $decoded = $this->decode($response, 'Token endpoint');
        $status = $response->getStatusCode();
        if ($status < 200 || $status >= 300) {
            $error = (string)($decoded['error'] ?? 'http_' . $status);
            $description = (string)($decoded['error_description'] ?? '');
            throw new TokenExchangeException(
                sprintf('Token endpoint rejected the code: %s%s', $error, $description !== '' ? ' (' . $description . ')' : ''),
                1747500004
            );
        }
        $accessToken = (string)($decoded['access_token'] ?? '');
        $idToken = (string)($decoded['id_token'] ?? '');
        if ($accessToken === '' || $idToken === '') {
            throw new TokenExchangeException('Token response lacks access_token or id_token (is the "openid" scope granted?).', 1747500005);
        }
        if (strcasecmp((string)($decoded['token_type'] ?? ''), 'Bearer') !== 0) {
            throw new TokenExchangeException('Unsupported token_type in token response.', 1747500006);
        }
        return new TokenSet(
            accessToken: $accessToken,
            idToken: $idToken,
            refreshToken: isset($decoded['refresh_token']) ? (string)$decoded['refresh_token'] : null,
            tokenType: 'Bearer',
            expiresIn: isset($decoded['expires_in']) ? (int)$decoded['expires_in'] : null,
            scope: isset($decoded['scope']) ? (string)$decoded['scope'] : null,
            raw: $decoded,
        );
    }

    /**
     * Userinfo claims; the caller must check that `sub` matches the ID token.
     *
     * @return array<string, mixed>
     * @throws TokenExchangeException
     */
    public function fetchUserinfo(ProviderMetadata $metadata, string $accessToken): array
    {
        if ($metadata->userinfoEndpoint === '') {
            return [];
        }
        try {
            $response = $this->requestFactory->request($metadata->userinfoEndpoint, 'GET', [
                'headers' => ['Accept' => 'application/json', 'Authorization' => 'Bearer ' . $accessToken],
                'timeout' => 10,
                'http_errors' => false,
            ]);
        } catch (\Throwable $e) {
            throw new TokenExchangeException('Userinfo endpoint unreachable: ' . $e->getMessage(), 1747500010, $e);
        }
        if ($response->getStatusCode() !== 200) {
            throw new TokenExchangeException(sprintf('Userinfo endpoint returned HTTP %d.', $response->getStatusCode()), 1747500011);
        }
        if (str_contains(strtolower($response->getHeaderLine('Content-Type')), 'application/jwt')) {
            // Signed userinfo responses are not supported; the ID token claims stay authoritative.
            $this->logger?->notice('oidc-connect: signed userinfo response ignored.');
            return [];
        }
        return $this->decode($response, 'Userinfo endpoint');
    }

    /**
     * @param array<string, string> $form
     */
    private function post(string $endpoint, array $form, OidcConnectSettings $settings, ProviderMetadata $metadata): ResponseInterface
    {
        $options = [
            'headers' => ['Accept' => 'application/json'],
            'timeout' => 15,
            'http_errors' => false,
        ];
        switch ($this->authMethod($settings, $metadata)) {
            case 'client_secret_basic':
                // RFC 6749 §2.3.1: credentials are form-urlencoded before base64.
                $options['headers']['Authorization'] = 'Basic ' . base64_encode(
                    rawurlencode($settings->clientId()) . ':' . rawurlencode($settings->clientSecret())
                );
                break;
            case 'client_secret_post':
                $form['client_id'] = $settings->clientId();
                $form['client_secret'] = $settings->clientSecret();
                break;
            default:
                $form['client_id'] = $settings->clientId();
        }
        $options['form_params'] = $form;
        try {
            return $this->requestFactory->request($endpoint, 'POST', $options);
        } catch (\Throwable $e) {
            throw new TokenExchangeException(sprintf('%s unreachable: %s', $endpoint, $e->getMessage()), 1747500001, $e);
        }
    }

    private function authMethod(OidcConnectSettings $settings, ProviderMetadata $metadata): string
    {
        if ($settings->clientSecret() === '') {
            return 'none';
        }
        $configured = $settings->tokenEndpointAuthMethod();
        if ($configured !== 'auto') {
            return $configured;
        }
        return in_array('client_secret_basic', $metadata->tokenEndpointAuthMethods, true) || !in_array('client_secret_post', $metadata->tokenEndpointAuthMethods, true)
            ? 'client_secret_basic'
            : 'client_secret_post';
    }

    /** @return array<string, mixed> */
    private function decode(ResponseInterface $response, string $label): array
    {
        try {
            $decoded = json_decode((string)$response->getBody(), true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new TokenExchangeException(sprintf('%s returned no JSON (HTTP %d).', $label, $response->getStatusCode()), 1747500002, $e);
        }
        if (!is_array($decoded)) {
            throw new TokenExchangeException(sprintf('%s returned no JSON object.', $label), 1747500003);
        }
        return $decoded;
    }
}
