#!/bin/sh
# Post-install script of the porthole (client) .deb and .rpm packages.
#
# The "porthole-client" user and group already exist (client-preinstall.sh). This script deliberately does NOT enable or
# start the service: it needs credentials first (`porthole login`). On an upgrade it restarts a running daemon so that it
# runs the new binary, and does nothing if the daemon is stopped.
#
# Called by dpkg as "configure [<previous version>]" (a previous version means upgrade) and by rpm with $1 = 1
# (install) or 2 (upgrade). Same structure as postinstall.sh of the portholed package.
set -e

case "$1" in
configure)
  if [ -n "${2:-}" ]; then action=upgrade; else action=install; fi
  ;;
1) action=install ;;
2) action=upgrade ;;
*)
  # abort-upgrade, abort-remove, abort-deconfigure: nothing to do.
  exit 0
  ;;
esac

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
  if [ "$action" = upgrade ]; then
    systemctl try-restart porthole.service >/dev/null 2>&1 || true
  fi
fi

if [ "$action" = install ]; then
  cat <<'MSG'

The porthole daemon is installed but NOT started. Next steps:
  1. sudo porthole login --config /etc/porthole/config.yaml <server-url> <token>
     sudo chown porthole-client: /etc/porthole/config.yaml && sudo chmod 0600 /etc/porthole/config.yaml
  2. Edit /etc/porthole/tunnels.yaml (the examples in it are disabled).
  3. sudo systemctl enable --now porthole
  4. sudo usermod -aG porthole-client "$USER"   (to add tunnels with `porthole http 3000`; log in again afterwards)
  Check with: porthole status

MSG
fi

exit 0
