#!/bin/sh
# Same-series official micro-updates. Never install a package just for a scan.
set -eu
test "$#" -eq 2 || { echo 'usage: security-updates LOCK TRUSTED_CA_BUNDLE' >&2; exit 2; }
lock=$1
trusted_ca=$2
. /etc/os-release
test "$ID:$VERSION_ID" = ubuntu:26.04
test -s "$lock"
test -s "$trusted_ca"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
dpkg-query -W -f='${binary:Package}\t${db:Status-Status}\n' | LC_ALL=C sort > "$tmp/before"
set --
while IFS= read -r entry || test -n "$entry"; do
    case "$entry" in ''|'#'*) continue;; esac
    case "$entry" in *[!a-zA-Z0-9.:+~=_-]*) echo "Invalid lock entry" >&2; exit 1;; esac
    package=${entry%%=*}
    version=${entry#*=}
    test "$package" != "$version"
    status=$(dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null || true)
    test "$status" = installed || continue
    installed=$(dpkg-query -W -f='${Version}' "$package")
    # A newer base may already contain the fix; never downgrade it.
    dpkg --compare-versions "$installed" ge "$version" && continue
    set -- "$@" "$entry"
done < "$lock"
if test "$#" -gt 0; then
    mkdir -p "$tmp/lists/partial"
    printf 'Types: deb\nURIs: https://snapshot.ubuntu.com/ubuntu/20261023T000000Z\nSuites: resolute-updates resolute-security\nComponents: main\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\nSnapshot: no\n' > "$tmp/security.sources"
    apt_security() {
        apt-get -o Dir::Etc::sourcelist="$tmp/security.sources" \
            -o Dir::State::lists="$tmp/lists" \
            -o Dir::Cache::pkgcache="$tmp/pkgcache.bin" -o Dir::Cache::srcpkgcache="$tmp/srcpkgcache.bin" \
            -o Dir::Etc::sourceparts=- -o Acquire::https::CaInfo="$trusted_ca" \
            -o Acquire::https::Verify-Peer=true -o Acquire::https::Verify-Host=true \
            -o Acquire::AllowInsecureRepositories=false -o APT::Get::AllowUnauthenticated=false \
            -o Acquire::Retries=5 "$@"
    }
    apt_security update
    DEBIAN_FRONTEND=noninteractive apt_security install -y --only-upgrade --no-install-recommends --no-remove "$@"
fi
while IFS= read -r entry || test -n "$entry"; do
    case "$entry" in ''|'#'*) continue;; esac
    package=${entry%%=*}
    version=${entry#*=}
    status=$(dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null || true)
    test "$status" = installed || continue
    dpkg --compare-versions "$(dpkg-query -W -f='${Version}' "$package")" ge "$version"
done < "$lock"
dpkg-query -W -f='${binary:Package}\t${db:Status-Status}\n' | LC_ALL=C sort > "$tmp/after"
# A security micro-update must not add/remove packages or change installed status.
cmp "$tmp/before" "$tmp/after"
printf 'UBUNTU_SECURITY_MICRO_UPDATES_OK\n'
