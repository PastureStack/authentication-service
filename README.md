# PastureStack Authentication Service

Authentication Service provides the compatible external-identity-provider,
token, identity lookup, reload, OpenID Connect, and SAML endpoints required by
the preserved control-platform authentication flow.

PastureStack is an independent community effort to preserve, audit, and modernize the Rancher 1.6 ecosystem. It is not affiliated with or endorsed by Rancher Labs or SUSE.

**Upstream:** [`rancher/rancher-auth-service`](https://github.com/rancher/rancher-auth-service). This GitHub fork preserves upstream history, authorship, dates, tags, licenses, and bundled dependency notices; PastureStack maintenance is consolidated into one commit after the preserved upstream boundary.

## Project status

Published maintenance release [`v0.4.45`](https://github.com/PastureStack/authentication-service/releases/tag/v0.4.45)
rebuilds the unchanged runtime with Go 1.27.3.
Its disposable AMD64 release builder pins the official curl 8.18.0-1ubuntu2.8
payload hashes, plus OpenSSL 3.5.5-1ubuntu3.7 from the signed frozen Ubuntu snapshot.
Linux user-space headers are pinned to 7.0.0-38.38; exact reviewed header-only
VEX statements do not claim a host-kernel fix or cover the Go runtime.
The existing raw-to-VEX equality, no-kernel-package and independent product
gates remain required. Component publication and anonymous asset readback passed;
matching Server assembly and runtime acceptance remain separate.

The current compatibility release is `v0.4.45`; existing published
tags and assets remain immutable. It retains the existing Ubuntu 26.04,
JWT, cookie, TLS, LDAP, GitHub, Shibboleth,
dependency, and build maintenance. It adds a provider-neutral OpenID Connect
authorization-code client with discovery, PKCE S256, nonce validation,
asymmetric ID-token verification, UserInfo subject matching, custom
certificate-authority support, and a test-before-enable recovery flow.
Successful staged sign-in also produces a short-lived, audience-bound,
single-use signed identity proof. The control platform uses that proof for an
explicit account-link or reassignment decision; profile fields are never
trusted as implicit account-matching keys.

Release `v0.4.42` retains the source-versus-policy separation introduced in
`v0.4.41` and also repairs the non-secret control-platform identity contract
for an already stored OIDC provider. Startup, reload, and policy-only updates
reconcile the OIDC user type, identity separator, provider selection, lookup
capability, and external-provider flag in a fail-closed order without reading
the client secret or repeating discovery. This lets databases upgraded from an
older release recover from incomplete common settings instead of failing the
final token exchange with `Identity externalIdType is invalid`.

The release separates OIDC identity-source changes from site-access
policy changes. An already-enabled provider can change access mode and its
OIDC user/group allowlist without repeating discovery, emitting a provider
reload generation, or repeating the five-minute local recovery ceremony.
Initial enablement, provider switches, and changes to the
discovery URL, client credentials, custom CA, scopes, PKCE, or identity claims
still require fresh local recovery and provider validation. Access expansion
requires a single-use MFA confirmation bound to the authenticated operator and
the canonical request digest. Unrestricted mode always persists an explicit
empty allowlist; restricted and required modes accept and deduplicate only
`oidc_user` and `oidc_group` identities. Stable error codes distinguish local
recovery, MFA confirmation, and invalid access-policy failures.
The unrestricted transition sends an explicit empty allowlist value on the
platform API wire. This prevents the generated client's `omitempty` behavior
from turning a requested clear into an omitted field and retaining stale
restricted identities in the database.
The legacy-settings importer now runs only before the encrypted `auth.config`
object exists. Once migration has completed, a process restart cannot replay
empty legacy OIDC keys over the authoritative access mode or allowlist. This
keeps restricted `oidc_user` and `oidc_group` entries intact across service and
Server container restarts while retaining the one-time migration path for old
installations.
Platform setting events can request a reload after a policy save. When the
active OIDC provider and identity source are unchanged, that reload now adopts
the persisted access policy in memory without repeating discovery, key
retrieval, or provider construction. Startup, first enablement, provider
switches, and identity-source changes retain the full initialization path.

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

The compiler archives are checksum-pinned Go 1.27.3 for Linux/amd64 and
Linux/arm64. This release's artifact qualification covers Linux/amd64 only,
not an ARM64 binary build. The compiler update includes the crypto/x509 fix
for CVE-2026-111943; authentication behavior is unchanged.

Set `VERSION_OVERRIDE=v0.4.45` for the reviewed identity-security compatibility
release. Packaging produces the deterministic, versioned
`authentication-service-0.4.45-linux-amd64.tar.xz` asset. The manually
dispatched release workflow runs the full test and validation suite twice,
requires byte-identical packages, verifies a fixed and attested security
scanner, publishes CycloneDX SBOMs and scan evidence, and publishes the
reviewed archive on GitHub. The build container runs without root privileges
and contains no nested Docker client or host socket. PastureStack Server
consumes that immutable release directly, so
operators do not need to host an artifact mirror.

Before enabling GitHub Enterprise, OpenID Connect, or URL-based SAML metadata,
the server operator must authorize every exact external origin through
`PASTURESTACK_AUTH_ALLOWED_EXTERNAL_ORIGINS`. The value is a comma-separated
list of origins such as `https://login.example.com,https://keys.example.com`;
entries must not contain paths, queries, credentials, or fragments. GitHub.com
and `api.github.com` are built in for the GitHub provider. Provider JSON,
discovery documents, metadata documents, pagination links, and redirects
cannot extend this list. Cross-origin redirects are rejected so OAuth client
secrets and bearer tokens are never forwarded to another origin.

The build image is pinned to an Ubuntu 26.04 digest and the official Ubuntu
snapshot recorded in `ubuntu-apt.lock`. Every directly installed APT package,
including GCC and libc development headers used only by race tests, has an
exact version. Snapshot updates and package versions must move together and
pass the manual security gate before release.

See [OpenID Connect](docs/openid-connect.md),
[COMPATIBILITY.md](COMPATIBILITY.md), [SECURITY.md](SECURITY.md), and
[ORIGIN.md](ORIGIN.md).

## License and attribution

The inherited project remains licensed under [Apache License 2.0](LICENSE). Copyright and attribution for inherited work and vendored dependencies remain with their respective authors and contributors. PastureStack contributors claim authorship only for their own changes.

## October 2026 security maintenance

Maintained Go builds select the patched Go 1.27.3 compiler without raising the existing Go language requirement. Ubuntu build/runtime stages apply the checksum-pinned `ca-certificates 20260816ubuntu0.26.04.1` security package after their frozen APT baseline; the final trust store and installed version are verified. Release artifacts must pass the repository's existing checks before publication.

## Full-severity security rebuild candidate

The next compatible release candidate is **v0.4.46** (not yet published). It keeps
the existing API and minimum Go language version while updating the compiler to
Go 1.27.3, `golang.org/x/net` to v0.60.0 and `golang.org/x/crypto` to v0.57.0.
The release gate now rejects every officially fixable vulnerability, regardless
of severity, and any unreviewed low/medium or unknown finding. The sole OpenPGP
VEX is bound to the exact module version and a recorded dependency graph proving
that the vulnerable package is not imported. Previously published v0.4.45 is
retained for provenance; it is not the fully patched candidate.
### Complete build-environment gate

The Dapper scan retains all severities and requires nonempty package analysis for the expected Go binaries. Any available fixed version fails, including Low, Medium and Unknown findings. Other Low/Medium findings require an exact package/version/PURL entry backed by the official vendor tracker. The pinned userspace kernel-header exception additionally requires the reviewed CVE set, actual header payload paths, and absence of kernel images/modules; it never permits an available fix. Unknown module findings require the separately verified exact source package graph, not a generic severity exemption.
