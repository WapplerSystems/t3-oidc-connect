# OIDC Connect for TYPO3

OpenID Connect login for TYPO3 v14, frontend and backend, configured per site
through **Site Settings**. Successor of `causal/oidc` + `wapplersystems/oidc-addons`
in WapplerSystems projects.

* Discovery: issuer + client id is all the provider configuration you need
* Authorization Code Flow with **PKCE (S256) always on**, state, nonce, browser-bound state cookie
* Full **ID token validation**: signature via JWKS (cached, rotation-aware), algorithm
  allow-list, `iss`, `aud`, `azp`, `exp`/`iat`, `nonce`, `at_hash`
* RFC 9207 `iss` response parameter check (mix-up defence)
* Login through the core authentication chain (session-id regeneration, rate limiting,
  login events, MFA stay intact)
* **RP-initiated logout** with `id_token_hint` (no Keycloak confirmation page)
* **Back-channel logout** for frontend and backend sessions, any session backend
* **Silent SSO** (`prompt=none`) for visitors who are already signed in at the provider
* **Backend login** ("Single Sign-On" tab on the TYPO3 login screen)
* Account linking of existing users by e-mail/username (only verified e-mail), group mapping
* `oidc:check` diagnostics and `oidc:provision` to create/update the Keycloak client
* Context variants: different client per environment in one `settings.yaml`

## Installation

```bash
composer require wapplersystems/oidc-connect
vendor/bin/typo3 extension:setup -e oidc_connect
```

Add the site set `wapplersystems/oidc-connect` to the site (`config/sites/<site>/config.yaml`,
`dependencies`), then configure it.

## Minimal configuration

`config/sites/<site>/settings.yaml`:

```yaml
oidcConnect:
  issuer: 'https://auth.example.com/realms/main'
  clientId: typo3-www
  users:
    storagePid: 14        # folder with the fe_users records
    defaultGroups: '1'    # every SSO user gets this group
```

The **client secret is never a site setting** (the settings editor would write a resolved
`%env()%` back as plain text, and resolved settings are cached on disk). It is looked up in:

1. the environment variable named in `oidcConnect.clientSecretEnv`
2. `OIDC_CONNECT_<SITE_IDENTIFIER>_CLIENT_SECRET` (e.g. `OIDC_CONNECT_MAIN_CLIENT_SECRET`)
3. `$GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['oidc_connect']['clientSecrets']['<site>']`
   (e.g. in `config/system/additional.php`)

Register these URLs at the provider (or let `oidc:provision` do it):

| Purpose | URL |
|---|---|
| Redirect URI (frontend) | `<site base>/oauth_callback` |
| Redirect URI (backend) | `<origin>/typo3/oidc-connect/callback` |
| Post-logout redirect | `<origin>/*` |
| Back-channel logout | `<site base>/oauth_backchannel_logout` |

`vendor/bin/typo3 oidc:check <site>` verifies discovery, issuer, JWKS, secret and URLs.

## Automatic client setup (Keycloak)

```bash
export OIDC_CONNECT_PROVISION_CLIENT_ID=typo3-provisioner
export OIDC_CONNECT_PROVISION_CLIENT_SECRET=...
vendor/bin/typo3 oidc:provision main --dry-run   # show what would change
vendor/bin/typo3 oidc:provision main             # create or update the client
```

The provisioner client is a confidential client in the same realm with *Service accounts
enabled* and the `realm-management` roles `manage-clients` and `view-clients`.

The command works for the **current application context**: it adds the redirect URIs of the
site base that is active there (`baseVariants` apply) and never removes URIs of other
environments sharing the client. Run it once per environment. A newly created client's secret
is only printed with `--show-secret`.

## Frontend usage

Links (Fluid, namespace `http://typo3.org/ns/WapplerSystems/OidcConnect/ViewHelpers`):

```html
<a href="{oidc:loginUrl()}">Log in</a>               <!-- returns to the current page -->
<a href="{oidc:loginUrl(redirect: '/members/')}">Log in</a>
<a href="{oidc:loginUrl(prompt: 'create')}">Register</a>
<a href="{oidc:logoutUrl()}">Log out</a>
```

or plain URLs: `/oauth_authorize?redirect=/members/` and `/oauth_logout`.

The content element **Login / logout button (SSO)** renders the right button and shows
error messages (`?oidc_error=<code>`).

Any local logout (felogin, `?logintype=logout`) closes the OIDC session binding as well; only
the logout route (and the backend logout) additionally ends the session at the provider.

## User provisioning

Lookup order on login:

1. record linked to `issuer` + `sub` (`tx_oidcconnect_issuer`, `tx_oidcconnect_subject`)
2. `users.linkByField` (`username` or `email`) equal to claim `users.linkByClaim` — only
   unlinked, non-deleted records, only if unambiguous, and for e-mail only when the provider
   reports `email_verified: true`
3. new record in `users.storagePid` (unless `users.mustExistLocally`); a new frontend user
   needs at least one group

Claim mapping and group mapping are YAML-only:

```yaml
oidcConnect:
  mapping:
    fe_users:
      email: email
      first_name: given_name
      last_name: family_name
      company: organization.name   # dotted path into nested claims
      country: '=DE'               # constant
  users:
    groupsClaim: groups            # e.g. Keycloak group membership mapper
  groupMapping:
    fe_groups:
      '/partner': '6'
      '/staff/*': '11,12'
```

Groups listed in `groupMapping` are managed: they are added and removed on every login;
other groups of the record stay untouched. `defaultGroups` are always added.

Listeners of `WapplerSystems\OidcConnect\Event\BeforeUserProvisionedEvent` can change the
data or deny the login.

## Backend login

```yaml
oidcConnect:
  backend:
    enable: true
    linkByField: email      # link existing be_users by verified e-mail
    createUsers: false
```

The backend has no site context: the extension configuration `backendSite` names the site
whose settings are used (default: the first site with `backend.enable`).

## Environments

```yaml
oidcConnect:
  issuer: 'https://auth.example.com/realms/main'
  clientId: typo3-www
  variants:
    - condition: 'applicationContext matches "#^Development#"'
      issuer: 'https://localhost:8443/realms/test'
      clientId: typo3-local
```

The first matching variant is merged over the base values.

## Silent SSO

`auth.silentSso: true` checks anonymous visitors once per `auth.silentSsoInterval` seconds
with `prompt=none`. Bots, non-HTML requests, prefetches and iframes are skipped. Every
first visit of a browser gets one extra redirect round trip, so only enable it where most
visitors are expected to have a provider session.

## Security notes

* Access and refresh tokens are discarded after login; only the ID token is kept (for
  `id_token_hint`) and deleted on logout.
* The callback refuses responses without a matching state record and browser cookie,
  issuer mismatches, unsigned or HMAC-signed tokens and replayed logout tokens.
* `uid`, `pid`, `password`, `usergroup`, `admin` and similar columns can never be written
  through claim mapping.

## License

GPL-2.0-or-later
