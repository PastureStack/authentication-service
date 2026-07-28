# PastureStack Authentication Service

Authentication Service provides the compatible external-identity-provider,
token, identity lookup, reload, OpenID Connect, and SAML endpoints required by
the preserved control-platform authentication flow.

PastureStack is an independent community effort to preserve, audit, and modernize the Rancher 1.6 ecosystem. It is not affiliated with or endorsed by Rancher Labs or SUSE.

**Upstream:** [`rancher/rancher-auth-service`](https://github.com/rancher/rancher-auth-service). This GitHub fork preserves upstream history, authorship, dates, tags, licenses, and bundled dependency notices; PastureStack maintenance is consolidated into one commit after the preserved upstream boundary.

## Project status

The current compatibility release retains the existing Ubuntu 26.04,
Go 1.26.5, Docker 29.4.2, JWT, cookie, TLS, LDAP, GitHub, Shibboleth,
dependency, and build maintenance. It adds a provider-neutral OpenID Connect
authorization-code client with discovery, PKCE S256, nonce validation,
asymmetric ID-token verification, UserInfo subject matching, custom
certificate-authority support, and a test-before-enable recovery flow.
Product-owned imports, executable names, CLI settings, client variables, and
operator messages use PastureStack naming.

## Configuration

Use `--platform-url`, `--platform-access-key`, and `--platform-secret-key`, or their `PLATFORM_*` environment variables. Historical `cattle-*` and `CATTLE_*` aliases remain for migration. RSA signing keys and the encrypted authentication configuration key are required. Set `PASTURESTACK_LOCALE=en-US` or `zh-TW` for operator messages.

## Build and test

From a Docker-capable Linux host:

```sh
make test
make build
make package
```

Set `VERSION_OVERRIDE=v0.2.3` for the reviewed OpenID Connect compatibility
release. Packaging produces the deterministic, versioned
`authentication-service-0.2.3-linux-amd64.tar.xz` asset. The manually
dispatched release workflow runs the full test and validation suite twice,
requires byte-identical packages, and publishes the reviewed archive on
GitHub. PastureStack Server consumes that immutable release directly, so
operators do not need to host an artifact mirror.

See [OpenID Connect](docs/openid-connect.md),
[COMPATIBILITY.md](COMPATIBILITY.md), [SECURITY.md](SECURITY.md), and
[ORIGIN.md](ORIGIN.md).

## License and attribution

The inherited project remains licensed under [Apache License 2.0](LICENSE). Copyright and attribution for inherited work and vendored dependencies remain with their respective authors and contributors. PastureStack contributors claim authorship only for their own changes.
