#!/bin/sh
# Pre-remove script of the porthole (client) .deb and .rpm packages: stops and disables the daemon on removal only.
#
# dpkg calls it with "remove" (or "upgrade", "deconfigure", ...); rpm with $1 = 0 on removal and 1 on upgrade.
# Upgrades are handled by client-postinstall.sh (try-restart), so they must not stop the service here.
# Same as preremove.sh of the portholed package.
set -e

case "$1" in
remove | 0)
  if [ -d /run/systemd/system ]; then
    systemctl stop porthole.service >/dev/null 2>&1 || true
    systemctl disable porthole.service >/dev/null 2>&1 || true
  fi
  ;;
esac

exit 0
