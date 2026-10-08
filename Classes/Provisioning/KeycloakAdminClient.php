<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\Provisioning;

use TYPO3\CMS\Core\Http\RequestFactory;

/**
 * Minimal Keycloak Admin REST client for provisioning an OIDC client.
 *
 * The client deliberately stores no credentials beyond the admin access token
 * for the lifetime of this object. The token is obtained once and never printed.
 */
final class KeycloakAdminClient
{
    private string $baseUrl = '';
    private string $realm = '';
    private ?string $accessToken = null;

    public function __construct(
        private readonly RequestFactory $requestFactory,
    ) {}

    /**
     * Splits a Keycloak issuer URL into the admin base URL and realm.
     *
     * @return array{baseUrl: string, realm: string}
     */
    public static function fromIssuer(string $issuer): array
    {
        $issuer = rtrim($issuer, '/');
        $parts = parse_url($issuer);
        if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
            throw new \InvalidArgumentException('Invalid issuer URL.');
        }

        $path = $parts['path'] ?? '';
        $needle = '/realms/';
        $position = strpos($path, $needle);
        if ($position === false) {
            throw new \InvalidArgumentException('Keycloak issuer must contain /realms/.');
        }

        $realm = substr($path, $position + strlen($needle));
        $realm = trim($realm, '/');
        if ($realm === '') {
            throw new \InvalidArgumentException('Keycloak issuer realm must not be empty.');
        }

        $pathBefore = substr($path, 0, $position);
        $baseUrl = $parts['scheme'] . '://' . $parts['host'];
        if (isset($parts['port'])) {
            $baseUrl .= ':' . $parts['port'];
        }
        if ($pathBefore !== '') {
            $baseUrl .= rtrim($pathBefore, '/');
        }

        return [
            'baseUrl' => rtrim($baseUrl, '/'),
            'realm' => $realm,
        ];
    }

    public function authenticate(string $issuer, string $clientId, string $clientSecret): void
    {
        ['baseUrl' => $baseUrl, 'realm' => $realm] = self::fromIssuer($issuer);
        $this->baseUrl = $baseUrl;
        $this->realm = $realm;

        $tokenUrl = rtrim($issuer, '/') . '/protocol/openid-connect/token';
        try {
            $response = $this->requestFactory->request($tokenUrl, 'POST', [
                'form_params' => [
                    'grant_type' => 'client_credentials',
                    'client_id' => $clientId,
                    'client_secret' => $clientSecret,
                ],
                'http_errors' => false,
            ]);
        } catch (\Throwable $e) {
            throw new \RuntimeException('Keycloak authentication request failed: ' . $e->getMessage(), 0, $e);
        }

        $status = $response->getStatusCode();
        $decoded = json_decode((string)$response->getBody(), true);
        if ($status < 200 || $status >= 300 || !is_string($decoded['access_token'] ?? null)) {
            throw new \RuntimeException(sprintf(
                'Keycloak authentication failed with HTTP %d: %s',
                $status,
                $this->errorFromResponse($decoded)
            ));
        }

        $this->accessToken = $decoded['access_token'];
    }

    public function findClient(string $clientId): ?array
    {
        $url = $this->adminUrl('/clients?clientId=' . urlencode($clientId));
        $response = $this->requestFactory->request($url, 'GET', [
            'headers' => ['Authorization' => $this->bearer()],
            'http_errors' => false,
        ]);

        $status = $response->getStatusCode();
        $decoded = json_decode((string)$response->getBody(), true);
        if ($status < 200 || $status >= 300) {
            throw new \RuntimeException(sprintf(
                'Keycloak findClient failed with HTTP %d: %s',
                $status,
                $this->errorFromResponse($decoded)
            ));
        }
        if (!is_array($decoded)) {
            return null;
        }

        foreach ($decoded as $client) {
            if (is_array($client) && ($client['clientId'] ?? '') === $clientId) {
                return $client;
            }
        }
        return null;
    }

    public function createClient(array $representation): string
    {
        $url = $this->adminUrl('/clients');
        $response = $this->requestFactory->request($url, 'POST', [
            'headers' => $this->jsonHeaders(),
            'body' => $this->encodeJson($representation),
            'http_errors' => false,
        ]);

        $status = $response->getStatusCode();
        $decoded = json_decode((string)$response->getBody(), true);
        if ($status !== 201) {
            throw new \RuntimeException(sprintf(
                'Keycloak createClient failed with HTTP %d: %s',
                $status,
                $this->errorFromResponse($decoded)
            ));
        }

        $location = $response->getHeader('Location');
        $locationPath = isset($location[0]) ? parse_url((string)$location[0], PHP_URL_PATH) : '';
        $path = trim((string)$locationPath, '/');
        if ($path === '') {
            throw new \RuntimeException('Keycloak createClient did not return a Location header.');
        }

        $segments = explode('/', $path);
        $id = (string)end($segments);
        if ($id === '') {
            throw new \RuntimeException('Keycloak createClient did not return a usable id in the Location header.');
        }

        return $id;
    }

    public function updateClient(string $id, array $representation): void
    {
        $url = $this->adminUrl('/clients/' . urlencode($id));
        $response = $this->requestFactory->request($url, 'PUT', [
            'headers' => $this->jsonHeaders(),
            'body' => $this->encodeJson($representation),
            'http_errors' => false,
        ]);

        $status = $response->getStatusCode();
        if ($status !== 204) {
            $decoded = json_decode((string)$response->getBody(), true);
            throw new \RuntimeException(sprintf(
                'Keycloak updateClient failed with HTTP %d: %s',
                $status,
                $this->errorFromResponse($decoded)
            ));
        }
    }

    public function getClientSecret(string $id): string
    {
        $url = $this->adminUrl('/clients/' . urlencode($id) . '/client-secret');
        $response = $this->requestFactory->request($url, 'GET', [
            'headers' => ['Authorization' => $this->bearer()],
            'http_errors' => false,
        ]);

        $status = $response->getStatusCode();
        $decoded = json_decode((string)$response->getBody(), true);
        if ($status < 200 || $status >= 300) {
            throw new \RuntimeException(sprintf(
                'Keycloak getClientSecret failed with HTTP %d: %s',
                $status,
                $this->errorFromResponse($decoded)
            ));
        }
        if (!is_string($decoded['value'] ?? null)) {
            throw new \RuntimeException('Keycloak getClientSecret response did not contain a value.');
        }

        return $decoded['value'];
    }

    private function adminUrl(string $suffix): string
    {
        if ($this->baseUrl === '' || $this->realm === '') {
            throw new \RuntimeException('Not authenticated. Call authenticate() first.');
        }
        return $this->baseUrl . '/admin/realms/' . $this->realm . $suffix;
    }

    private function bearer(): string
    {
        if ($this->accessToken === null) {
            throw new \RuntimeException('Not authenticated. Call authenticate() first.');
        }
        return 'Bearer ' . $this->accessToken;
    }

    private function jsonHeaders(): array
    {
        return [
            'Content-Type' => 'application/json',
            'Authorization' => $this->bearer(),
        ];
    }

    private function encodeJson(array $representation): string
    {
        try {
            return json_encode($representation, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (\JsonException $e) {
            throw new \RuntimeException('Could not encode client representation as JSON: ' . $e->getMessage(), 0, $e);
        }
    }

    private function errorFromResponse(mixed $decoded): string
    {
        if (is_array($decoded)) {
            foreach (['error', 'errorMessage'] as $key) {
                if (is_string($decoded[$key] ?? null) && $decoded[$key] !== '') {
                    return $decoded[$key];
                }
            }
        }
        return 'unknown error';
    }
}
