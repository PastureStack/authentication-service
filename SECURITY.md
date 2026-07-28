# Security Policy

## Supported state

The `v0.2.x` compatibility line is maintained for the matching PastureStack
Server release. New authentication-provider combinations remain subject to
administrator testing before activation.

## Security boundaries

- RSA private keys, configuration-encryption keys, provider secrets, API credentials, tokens, cookies, OpenID Connect authorization codes, and SAML assertions are sensitive.
- Insecure identity-provider metadata TLS is a compatibility escape hatch and must remain disabled by default.
- Redirect targets must stay within the configured allowlist and control-platform API host.
- OpenID Connect discovery, authorization, token, UserInfo, and signing-key
  endpoints require HTTPS except for explicit loopback tests. Custom
  certificate authorities extend the system trust store; they never disable
  certificate verification.
- OpenID Connect ID tokens accept only supported asymmetric signatures and
  require issuer, audience, expiry, issued-at, and nonce validation. UserInfo
  must return the same subject as the ID token.
- A staged provider test must not expose the upstream access token or create a
  browser session. Activation uses a fresh authorization code and the normal
  platform token endpoint.
- Do not commit keys, credentials, tokens, encrypted production settings, identity data, or live assertions.

## Reporting

Report suspected vulnerabilities through this repository's private security advisory channel. Do not include credentials, tokens, or personal identity data in a public issue.
