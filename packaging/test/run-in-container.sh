#!/usr/bin/env bash
# Runs one upgrade test in a throw-away container.
#
# usage: run-in-container.sh <image> <deb|rpm> <dir with old packages> <dir with new packages>
#
# The files are copied in with `docker cp` instead of a bind mount (a mount is not needed, and bind mounts of large
# trees are slow or fragile with Docker Desktop). The container needs network access: apt and dnf fetch dependencies
# (shadow-utils).
set -euo pipefail
image=${1:?usage: run-in-container.sh <image> <deb|rpm> <old dir> <new dir>}
kind=${2:?usage: run-in-container.sh <image> <deb|rpm> <old dir> <new dir>}
old=${3:?usage: run-in-container.sh <image> <deb|rpm> <old dir> <new dir>}
new=${4:?usage: run-in-container.sh <image> <deb|rpm> <old dir> <new dir>}
case "$kind" in
deb | rpm) ;;
*)
  echo "kind must be deb or rpm" >&2
  exit 2
  ;;
esac
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Git Bash on Windows: docker.exe wants Windows paths for the host side and must not get the container paths rewritten.
export MSYS_NO_PATHCONV=1
native() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s\n' "$1"; fi; }

cid=$(docker create --entrypoint sleep "$image" 3600)
trap 'docker rm -f "$cid" >/dev/null 2>&1' EXIT
docker start "$cid" >/dev/null
docker cp "$(native "$here")" "$cid:/t"
docker cp "$(native "$old")" "$cid:/old"
docker cp "$(native "$new")" "$cid:/new"
docker exec "$cid" bash "/t/upgrade-$kind.sh" /old /new
