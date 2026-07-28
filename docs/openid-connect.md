# OpenID Connect

PastureStack Authentication Service implements a provider-neutral OpenID
Connect authorization-code client. The implementation is not tied to a
specific identity-provider vendor.

## Provider requirements

The provider must publish a valid OpenID Connect discovery document and
support:

- the authorization-code flow;
- the `openid` scope;
- an asymmetric ID-token signing algorithm supported by the service;
- a JSON Web Key Set endpoint;
- a UserInfo endpoint;
- `client_secret_basic` or `client_secret_post`;
- PKCE S256 when PKCE is enabled.

Discovery and all advertised endpoints require HTTPS. Loopback HTTP is
accepted only by automated tests. A private provider can be trusted by pasting
its PEM-encoded certificate authority into the configuration; TLS verification
remains enabled.

Register this redirect URI with the provider:

```text
https://CONTROL-PLATFORM/login/oidc-auth
```

Use the actual scheme and authority through which browsers access the control
platform.

## Configuration

The administrative interface requests:

- a display name;
- the discovery-document URL;
- a client ID and client secret;
- scopes, including `openid`;
- optional PKCE S256;
- username, display-name, email, and groups claim names;
- an optional private certificate authority.

The client secret is encrypted by the existing authentication-configuration
mechanism. API responses expose only whether a secret is already set.

User and group identities are namespaced by issuer and subject so that two
providers cannot accidentally produce the same external identity.

## Safe activation and recovery

1. Validate the proposed configuration. Discovery, endpoint, TLS, client, and
   signing-algorithm checks run without changing the active provider.
2. Complete one real provider sign-in as a test. The returned provider access
   token and temporary service token are discarded. The service returns only
   a short-lived, audience-bound, single-use signed identity proof.
3. Review the exact issuer and subject and explicitly bind the identity to a
   platform account, create a new account, or reassign an existing link.
   Username and email claims are display data and are never implicit matching
   keys.
4. Activate the provider with the one-use account-and-identity-bound switch
   ticket. The normal platform token endpoint creates the authenticated
   session only after the selected account relationship is durable.

The platform account remains the authorization principal, so changing login
providers does not recreate project memberships or administrator status.
Active local administrator credentials remain available as a recovery path
when an external provider is unavailable. Normal local recovery still
requires the account's configured multi-factor authentication; the
transactional switch ticket is short-lived and can be used only once. If the
final session exchange fails, the Web Console restores the prior provider and
the original administrator session.

## Token validation

The service validates the discovery issuer, signature algorithm, signing key,
issuer, audience, authorized party where required, expiry, issued-at time,
nonce, and access-token hash when present. It rejects unsigned and symmetric
ID tokens. The UserInfo `sub` value must exactly match the verified ID-token
subject before profile claims are merged.
