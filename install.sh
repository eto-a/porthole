#!/bin/sh
# install.sh - install porthole (the client) or portholed (the server) from a GitHub release, without building.
#
#   curl -fsSL https://raw.githubusercontent.com/eto-a/porthole/main/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/eto-a/porthole/main/install.sh | sh -s -- --server
#
# Run with --help for the options. What it does:
#   1. detects the OS (Linux, macOS) and CPU (amd64, arm64);
#   2. picks a release: the latest stable one, or the newest pre-release while no stable release exists;
#   3. downloads the archive (or, for --server on Debian/Ubuntu and RHEL/Fedora, the .deb/.rpm package) and
#      checks its SHA-256 against checksums.txt of the same release;
#   4. if cosign is installed, also verifies the Sigstore signature of checksums.txt (made by the release workflow);
#   5. installs it, using sudo only when needed.
# Nothing is installed when a check fails. Windows is not supported by this script.
#
# The overall structure (everything wrapped in main() and called on the last line, curl or wget fallback, sudo
# detection) follows tailscale's installer, https://github.com/tailscale/tailscale/blob/main/scripts/installer.sh
# (BSD-3-Clause); no code was copied from it.
#
# Environment (for mirrors and tests):
#   PORTHOLE_DOWNLOAD_URL  base URL of the release downloads, default https://github.com/eto-a/porthole/releases/download
#                          (files are fetched from <base>/<tag>/<file>)
#   PORTHOLE_API_URL       GitHub API of the repository, default https://api.github.com/repos/eto-a/porthole

set -eu

REPO="eto-a/porthole"
RELEASES_PAGE="https://github.com/${REPO}/releases"
COSIGN_IDENTITY_REGEXP='^https://github.com/eto-a/porthole/\.github/workflows/release\.yml@refs/tags/v'
COSIGN_OIDC_ISSUER='https://token.actions.githubusercontent.com'

# Settings (filled in by parse_args) and state (filled in by the steps below). Plain globals: POSIX sh has no `local`.
want_server=0
want_client=0
version=""
prerelease=0
bin_dir=""
use_archive=0
verify_signature=1
dry_run=0

component=""
os=""
arch=""
fetcher=""
tmp=""
tag=""
ver=""
base_url=""
api_url=""
method=""
pkg_type=""
asset=""

say() {
  printf '%s\n' "$*"
}

warn() {
  printf 'install.sh: warning: %s\n' "$*" >&2
}

die() {
  printf 'install.sh: error: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Install porthole (client) or portholed (server) from a GitHub release.

Usage: install.sh [options]

  --client            install the client, porthole (default)
  --server            install the server, portholed; on Debian/Ubuntu and RHEL/Fedora this installs the .deb/.rpm
                      package (systemd unit and "porthole" user included), elsewhere only the binary
  --version VERSION   install this release, for example v0.1.0 (default: the latest stable release; while there is
                      no stable release yet, the newest pre-release)
  --prerelease        take the newest release including pre-releases, even if a stable release exists
  --bin-dir DIR       install the binary into DIR (default: /usr/local/bin, or ~/.local/bin without root access)
  --archive           with --server, install the binary from the archive even where a package could be used
  --no-verify-signature
                      do not verify the cosign signature even if cosign is installed (SHA-256 is always checked)
  --dry-run           print what would be done and exit; nothing is downloaded or installed
  -h, --help          show this help

Examples:
  curl -fsSL https://raw.githubusercontent.com/eto-a/porthole/main/install.sh | sh
  curl -fsSL https://raw.githubusercontent.com/eto-a/porthole/main/install.sh | sh -s -- --server --version v0.1.0
EOF
}

cleanup() {
  if [ -n "$tmp" ]; then
    rm -rf "$tmp"
  fi
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
    --server) want_server=1 ;;
    --client) want_client=1 ;;
    --version)
      [ $# -ge 2 ] || die "--version needs a value"
      version=$2
      shift
      ;;
    --version=*) version=${1#--version=} ;;
    --prerelease) prerelease=1 ;;
    --bin-dir)
      [ $# -ge 2 ] || die "--bin-dir needs a value"
      bin_dir=$2
      shift
      ;;
    --bin-dir=*) bin_dir=${1#--bin-dir=} ;;
    --archive) use_archive=1 ;;
    --no-verify-signature) verify_signature=0 ;;
    --dry-run) dry_run=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    *) die "unknown option: $1 (see --help)" ;;
    esac
    shift
  done

  if [ "$want_server" = 1 ] && [ "$want_client" = 1 ]; then
    die "--server and --client cannot be combined; run the script once for each"
  fi
  if [ "$want_server" = 1 ]; then
    component=portholed
  else
    component=porthole
  fi
  if [ -n "$version" ] && [ "$prerelease" = 1 ]; then
    die "--version and --prerelease cannot be combined"
  fi
  if [ -n "$bin_dir" ]; then
    case "$bin_dir" in
    /*) ;;
    *) die "--bin-dir must be an absolute path" ;;
    esac
  fi

  base_url=${PORTHOLE_DOWNLOAD_URL:-https://github.com/${REPO}/releases/download}
  api_url=${PORTHOLE_API_URL:-https://api.github.com/repos/${REPO}}
}

detect_platform() {
  case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  MINGW* | MSYS* | CYGWIN* | Windows_NT)
    die "Windows is not supported by this script; download the .zip for your CPU from ${RELEASES_PAGE}"
    ;;
  *) die "unsupported operating system $(uname -s): only Linux and macOS are supported; see ${RELEASES_PAGE}" ;;
  esac

  case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) die "unsupported CPU architecture $(uname -m): only amd64 and arm64 are supported; see ${RELEASES_PAGE}" ;;
  esac
}

detect_fetcher() {
  if command -v curl >/dev/null 2>&1; then
    fetcher=curl
  elif command -v wget >/dev/null 2>&1; then
    fetcher=wget
  else
    die "need curl or wget to download files; please install one of them"
  fi
}

# fetch URL DEST: download URL to the file DEST. HTTPS URLs are fetched over TLS 1.2+ only, redirects included.
fetch() {
  case "$fetcher" in
  curl)
    case "$1" in
    https://*)
      curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 \
        --connect-timeout 15 --max-time 600 -o "$2" "$1"
      ;;
    *)
      curl -fsSL --retry 3 --connect-timeout 15 --max-time 600 -o "$2" "$1"
      ;;
    esac
    ;;
  wget)
    # GNU wget: HTTPS only (no downgrade by redirect) and TLS 1.2+. BusyBox wget has neither option; there the plain
    # call is the best that can be done, so prefer curl on such systems.
    case "$1" in
    https://*)
      if wget --help 2>&1 | grep -q -e '--https-only'; then
        wget -q -T 30 --https-only --secure-protocol=TLSv1_2 -O "$2" "$1"
      else
        wget -q -T 30 -O "$2" "$1"
      fi
      ;;
    *)
      wget -q -T 30 -O "$2" "$1"
      ;;
    esac
    ;;
  esac
}

# json_tag FILE: first "tag_name" value in a GitHub API response (a release, or a list of releases, newest first).
json_tag() {
  tr ',' '\n' <"$1" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1
}

# valid_tag TAG: true for vMAJOR.MINOR.PATCH with an optional pre-release suffix, nothing else. The tag ends up in
# download URLs and file names, so no "/", ".." or other surprises (a hostile PORTHOLE_API_URL can return any tag).
valid_tag() {
  printf '%s
' "$1" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'
}

# resolve_version sets $tag (v1.2.3) and $ver (1.2.3).
#
# Without --version it asks the GitHub API (60 requests per hour per IP without a token; --version avoids the call).
# Stable first: /releases/latest returns the newest non-pre-release. It answers 404 while the project has only
# pre-releases, and then the newest entry of /releases (pre-releases included) is used, with a notice. --prerelease
# goes straight to /releases. The list is sorted by creation date, newest first.
resolve_version() {
  if [ -n "$version" ]; then
    ver=${version#v}
    tag="v$ver"
    valid_tag "$tag" || die "invalid version \"$version\"; expected something like v0.1.0 or v0.1.0-alpha.1"
    return
  fi

  tag=""
  if [ "$prerelease" = 0 ]; then
    if fetch "${api_url}/releases/latest" "$tmp/release.json" 2>/dev/null; then
      tag=$(json_tag "$tmp/release.json")
    fi
    if [ -z "$tag" ]; then
      say "No stable release found (or the GitHub API did not answer); looking at pre-releases too."
    fi
  fi
  if [ -z "$tag" ]; then
    fetch "${api_url}/releases?per_page=1" "$tmp/releases.json" ||
      die "could not query the GitHub API (rate limit? no network?); pass --version vX.Y.Z to skip the lookup, see ${RELEASES_PAGE}"
    tag=$(json_tag "$tmp/releases.json")
    [ -n "$tag" ] || die "no release found at ${RELEASES_PAGE}"
    case "$tag" in
    *-*) say "Using the pre-release ${tag}." ;;
    esac
  fi
  valid_tag "$tag" || die "unexpected release tag \"$tag\" from the GitHub API"
  ver=${tag#v}
}

# have_privileges: true when root, or when sudo or doas exists.
have_privileges() {
  [ "$(id -u)" = 0 ] || command -v sudo >/dev/null 2>&1 || command -v doas >/dev/null 2>&1
}

# as_root CMD...: run a command as root, through sudo or doas unless already root.
as_root() {
  if [ "$(id -u)" = 0 ]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    say "Using sudo: $*"
    sudo "$@"
  elif command -v doas >/dev/null 2>&1; then
    say "Using doas: $*"
    doas "$@"
  else
    die "root privileges are needed to run \"$*\", but neither sudo nor doas is available; run as root or use --bin-dir"
  fi
}

# detect_package_type sets $pkg_type to deb or rpm when the host is a Debian or RHEL family distribution.
detect_package_type() {
  pkg_type=""
  [ -r /etc/os-release ] || return 0
  # shellcheck source=/dev/null
  ids=$(. /etc/os-release && printf ' %s %s ' "${ID:-}" "${ID_LIKE:-}")
  case "$ids" in
  *" debian "* | *" ubuntu "*)
    if command -v dpkg >/dev/null 2>&1; then pkg_type=deb; fi
    ;;
  *" rhel "* | *" fedora "* | *" centos "*)
    if command -v rpm >/dev/null 2>&1; then pkg_type=rpm; fi
    ;;
  esac
}

# choose_method sets $method (package or archive), $pkg_type and $asset.
choose_method() {
  method=archive
  if [ "$want_server" = 1 ] && [ "$os" = linux ]; then
    if [ "$use_archive" = 1 ]; then
      :
    elif ! have_privileges; then
      warn "no root access (and no sudo), so the package cannot be installed; installing only the binary"
    else
      detect_package_type
      if [ -n "$pkg_type" ]; then
        method=package
      fi
    fi
  fi

  set_asset
}

# set_asset sets $asset from $method.
set_asset() {
  if [ "$method" = package ]; then
    asset="${component}_${ver}_${os}_${arch}.${pkg_type}"
  else
    asset="${component}_${ver}_${os}_${arch}.tar.gz"
  fi
}

# choose_bin_dir sets $bin_dir (archive installs only).
choose_bin_dir() {
  [ -z "$bin_dir" ] || return 0
  if [ "$(id -u)" = 0 ] || [ -w /usr/local/bin ]; then
    bin_dir=/usr/local/bin
  else
    [ -n "${HOME:-}" ] || die "HOME is not set; use --bin-dir"
    bin_dir="$HOME/.local/bin"
  fi
}

# dir_writable DIR: true if the current user can write to DIR, or to the nearest existing parent when DIR is missing.
# It never creates anything (the dry run uses it too).
dir_writable() {
  d=$1
  while [ ! -d "$d" ]; do
    parent=$(dirname "$d")
    [ "$parent" != "$d" ] || return 1
    d=$parent
  done
  [ -w "$d" ]
}

print_plan() {
  if [ "$want_server" = 1 ]; then role=server; else role=client; fi
  if [ "$(id -u)" = 0 ]; then who="as root"; else who="through sudo/doas"; fi

  say "porthole installer (dry run: nothing will be downloaded or installed)"
  say "  component: ${component} (${role})"
  say "  release:   ${tag}"
  say "  platform:  ${os}/${arch}"
  if [ "$method" = package ]; then
    if [ "$pkg_type" = deb ]; then cmd="dpkg -i"; else cmd="dnf/yum install"; fi
    say "  method:    ${pkg_type} package"
    say "  install:   ${cmd} ${asset} (${who}); the binary from the archive is used if the release has no package"
  else
    say "  method:    binary from the archive"
    if dir_writable "$bin_dir"; then
      say "  install:   ${bin_dir}/${component}"
    else
      say "  install:   ${bin_dir}/${component} (${who})"
    fi
  fi
  say "  download:  ${base_url}/${tag}/${asset}"
  say "             ${base_url}/${tag}/checksums.txt"
  say "  verify:    SHA-256 against checksums.txt"
  if [ "$verify_signature" = 0 ]; then
    say "             cosign signature: skipped (--no-verify-signature)"
  elif command -v cosign >/dev/null 2>&1; then
    say "             cosign signature of checksums.txt (${base_url}/${tag}/checksums.txt.sigstore.json)"
  else
    say "             cosign signature: skipped, cosign is not installed"
  fi
}

# sha256_of FILE: print the SHA-256 of FILE.
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{ print $1 }'
  else
    die "need sha256sum or shasum to verify the download; refusing to install unverified files"
  fi
}

verify_checksum() {
  expected=$(awk -v n="$asset" '{ f = $2; sub(/^\*/, "", f); if (f == n) { print $1; exit } }' "$tmp/checksums.txt")
  [ -n "$expected" ] || die "checksums.txt of ${tag} has no entry for ${asset}"
  actual=$(sha256_of "$tmp/$asset")
  if [ "$expected" != "$actual" ]; then
    die "SHA-256 mismatch for ${asset}: expected ${expected}, got ${actual}; refusing to install"
  fi
  say "SHA-256 of ${asset} matches checksums.txt."
}

verify_signature_if_possible() {
  if [ "$verify_signature" = 0 ]; then
    warn "cosign signature check skipped (--no-verify-signature)"
    return 0
  fi
  if ! command -v cosign >/dev/null 2>&1; then
    say "cosign is not installed: skipping the signature check. SHA-256 alone only protects against a corrupted"
    say "download, not against a tampered release; install cosign (https://docs.sigstore.dev) to verify the signature."
    return 0
  fi
  fetch "${base_url}/${tag}/checksums.txt.sigstore.json" "$tmp/checksums.txt.sigstore.json" ||
    die "could not download checksums.txt.sigstore.json of ${tag}; re-run with --no-verify-signature to skip the signature check"
  if ! cosign verify-blob \
    --bundle "$tmp/checksums.txt.sigstore.json" \
    --certificate-identity-regexp "$COSIGN_IDENTITY_REGEXP" \
    --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
    "$tmp/checksums.txt" >"$tmp/cosign.log" 2>&1; then
    cat "$tmp/cosign.log" >&2
    die "cosign could not verify the signature of checksums.txt; refusing to install"
  fi
  say "cosign signature of checksums.txt is valid."
}

install_package() {
  say "Installing ${asset} (${pkg_type} package)..."
  case "$pkg_type" in
  deb)
    as_root dpkg -i "$tmp/$asset" </dev/null
    ;;
  rpm)
    if command -v dnf >/dev/null 2>&1; then
      as_root dnf install -y "$tmp/$asset" </dev/null
    elif command -v yum >/dev/null 2>&1; then
      as_root yum install -y "$tmp/$asset" </dev/null
    else
      as_root rpm -Uvh "$tmp/$asset" </dev/null
    fi
    ;;
  esac
  say ""
  say "Installed ${component} ${ver}. The service is not started yet: edit /etc/porthole/portholed.yaml, then run"
  say "  sudo systemctl enable --now portholed"
}

install_archive() {
  mkdir "$tmp/extract"
  tar -xzf "$tmp/$asset" -C "$tmp/extract" "$component" ||
    die "${asset} does not contain ${component}"
  [ -f "$tmp/extract/$component" ] || die "${asset} does not contain ${component}"

  say "Installing ${component} to ${bin_dir}..."
  if dir_writable "$bin_dir"; then
    mkdir -p "$bin_dir"
    install -m 0755 "$tmp/extract/$component" "$bin_dir/$component"
  else
    as_root mkdir -p "$bin_dir"
    as_root install -m 0755 "$tmp/extract/$component" "$bin_dir/$component"
  fi
  say "Installed ${bin_dir}/${component} ${ver}."

  case ":${PATH:-}:" in
  *":${bin_dir}:"*) ;;
  *) warn "${bin_dir} is not in your PATH; add it, for example: export PATH=\"${bin_dir}:\$PATH\"" ;;
  esac
}

print_next_steps() {
  say ""
  if [ "$want_server" = 1 ]; then
    if [ "$method" = archive ]; then
      say "Only the binary was installed. To run it as a service, see the systemd unit and the example"
      say "configuration in https://github.com/${REPO}/tree/main/deploy (the unit expects /usr/bin/portholed)."
    fi
    say "Quickstart for the server: https://github.com/${REPO}#1-server"
  else
    say "Next: porthole login https://your-server.example.com <token>, then porthole http 8080"
    say "Quickstart: https://github.com/${REPO}#2-client"
    if [ "$os" = darwin ]; then
      say "To keep tunnels up as a service (available from v0.4): porthole service install --user"
      say "(a LaunchAgent for your login; run it with sudo for a system LaunchDaemon instead)."
    fi
    say "To keep tunnels up as a service: https://github.com/${REPO}#run-the-client-as-a-service"
  fi
}

main() {
  parse_args "$@"
  detect_platform
  detect_fetcher

  tmp=$(mktemp -d 2>/dev/null || mktemp -d -t porthole-install) || die "could not create a temporary directory"
  trap cleanup EXIT
  trap 'exit 1' HUP INT TERM

  resolve_version
  choose_method
  if [ "$method" = archive ]; then
    choose_bin_dir
  fi

  if [ "$dry_run" = 1 ]; then
    print_plan
    return 0
  fi

  say "Installing ${component} ${tag} for ${os}/${arch}."
  fetch "${base_url}/${tag}/checksums.txt" "$tmp/checksums.txt" ||
    die "could not download ${base_url}/${tag}/checksums.txt (does release ${tag} exist? see ${RELEASES_PAGE})"
  if ! fetch "${base_url}/${tag}/${asset}" "$tmp/$asset"; then
    [ "$method" = package ] ||
      die "could not download ${base_url}/${tag}/${asset} (does release ${tag} have this file? see ${RELEASES_PAGE})"
    # Releases made before the packages existed (v0.1.0-alpha.1) only have archives.
    warn "could not download ${asset}; installing the binary from the archive instead (no systemd unit, no user)"
    method=archive
    set_asset
    choose_bin_dir
    fetch "${base_url}/${tag}/${asset}" "$tmp/$asset" ||
      die "could not download ${base_url}/${tag}/${asset} (does release ${tag} have this file? see ${RELEASES_PAGE})"
  fi

  verify_checksum
  verify_signature_if_possible

  if [ "$method" = package ]; then
    install_package
  else
    install_archive
  fi
  print_next_steps
}

# Everything above is only function definitions. main runs on the last line so that a truncated download (curl | sh)
# cannot execute half of the script.
main "$@"
