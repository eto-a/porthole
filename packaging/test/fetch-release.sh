#!/usr/bin/env bash
# Downloads the linux/amd64 .deb and .rpm packages of a published release and verifies them against checksums.txt.
#
# usage: fetch-release.sh <tag, e.g. v0.3.0-alpha.2> <destination directory>
#
# The checksum file comes from the same release, so this catches a corrupt or truncated download, not a compromised
# release; the provenance of a release is checked with `gh attestation verify` (see docs/install.md).
set -euo pipefail
tag=${1:?usage: fetch-release.sh <tag> <dir>}
dest=${2:?usage: fetch-release.sh <tag> <dir>}
ver=${tag#v}
base=https://github.com/eto-a/porthole/releases/download/$tag

mkdir -p "$dest"
cd "$dest"
curl -fsSL --retry 3 --max-time 120 -o checksums.txt "$base/checksums.txt"
for name in "portholed_${ver}_linux_amd64.deb" "portholed_${ver}_linux_amd64.rpm" \
  "porthole_${ver}_linux_amd64.deb" "porthole_${ver}_linux_amd64.rpm"; do
  curl -fsSL --retry 3 --max-time 120 -o "$name" "$base/$name"
  awk -v f="$name" '$2 == f' checksums.txt | sha256sum --check --strict -
done
