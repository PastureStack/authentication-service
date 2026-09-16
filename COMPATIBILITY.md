# Compatibility Contract

The migration preserves the established `/v1-rancher-auth` route prefix, token and identity schemas, database setting keys, encrypted provider configuration, SAML callback behavior, and generated client resource shapes.

Preferred settings use `platform-*`, `PLATFORM_*`, and `PASTURESTACK_AUTH_ALLOW_INSECURE_IDP_METADATA_TLS`. Historical `cattle-*`, `CATTLE_*`, the route prefix above, generated `RancherClient` types, and vendored `github.com/rancher/*` paths remain only as HTTP, data, or inherited dependency contracts.

The generic OpenID Connect provider preserves the existing redirect-based
authentication contract. It uses the authorization-code flow and supports
`client_secret_basic` or `client_secret_post`, PKCE S256, discovery, UserInfo,
and asymmetric ID-token signatures. The provider is staged and tested before
the active authentication method changes. Existing local authentication
remains the recovery path until a second, fresh authorization-code exchange
creates a normal platform session.

## OIDC site-access policy updates

OIDC provider initialization and site-access authorization are independent
transactions. Updating only `accessMode` or `allowedIdentities` on an already
enabled, unchanged OIDC provider must not repeat discovery, key retrieval, or
provider initialization. Initial enablement, changing provider type, or
changing the OIDC identity source still requires a fresh local-recovery check
and successful provider initialization.

Expanding access requires a one-time Engine MFA security confirmation bound to
the authenticated operator, purpose `oidcAccessPolicyUpdate`, and the canonical
SHA-256 request digest. Reducing access does not require step-up confirmation.
Unrestricted mode persists a non-null empty allowlist. Restricted and required
mode entries are canonicalized and deduplicated by `externalIdType` plus
`externalId`; only `oidc_user` and `oidc_group` are accepted.
The empty allowlist must be present as an explicit `value: ""` field in the
platform setting update. Generated client omission rules must not turn the
clear operation into a no-op.

Operator lifecycle messages support `en-US` and `zh-TW`. Tokens, usernames,
groups, identity-provider data, OpenID Connect claims, SAML documents,
database settings, HTTP payloads, and protocol errors are not translated.

Before release, validate RSA signing, token issuance and expiry, cookie
security, provider reload, LDAP and GitHub login, OpenID Connect discovery,
PKCE, nonce, issuer, audience, asymmetric signatures, UserInfo subject
matching, Shibboleth metadata TLS, SAML redirects and allowlists, encryption
migration, and rollback.
