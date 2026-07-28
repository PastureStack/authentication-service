# Bundled control API client

This directory preserves the exact control API client source previously bundled
with the authentication service. Its upstream source is
[`rancher/go-rancher`](https://github.com/rancher/go-rancher) at commit
`cc9af4572762fc6ae01f5f9bebbc359506c2f6dd` (2017-05-18).

The snapshot remains under its inherited Apache License 2.0; see `LICENSE` in
this directory. PastureStack does not claim authorship of the inherited code.
The imported Go packages were moved byte-for-byte from the repository's
reviewed `vendor` tree at PastureStack commit
`62726c0b03b64848ff9d0e1d8ff5e965007efe61` before dependency regeneration.
Relative to the referenced upstream commit, that reviewed tree already
normalizes the Logrus import-path casing. Non-runtime build automation, legacy
dependency configuration, ignore files, and the upstream README are omitted;
their history remains available in the parent repository and at the upstream
source link above. The root module uses a local `replace` directive so these
reviewed source bytes and their license are available without an unversioned
network fetch.
