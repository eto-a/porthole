#!/bin/sh
# Pre-remove script of the portholed .deb and .rpm packages: stops and disables the service on removal only.
#
# dpkg calls it with "remove" (or "upgrade", "deconfigure", ...); rpm with $1 = 0 on removal and 1 on upgrade.
# Upgrades are handled by postinstall.sh (try-restart), so they must not stop the service here.
# Compare caddyserver/dist scripts/preremove.sh.
set -e

case "$1" in
remove | 0)
  if [ -d /run/systemd/system ]; then
    systemctl stop portholed.service >/dev/null 2>&1 || true
    systemctl disable portholed.service >/dev/null 2>&1 || true
  fi
  ;;
esac

exit 0
