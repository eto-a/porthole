#!/bin/sh
# Post-install script of the porthole (client) .deb and .rpm packages.
#
# The "porthole-client" user and group already exist (client-preinstall.sh). This script deliberately does NOT enable or
# start the service: it needs credentials first (`porthole login`). On an upgrade it restarts a running daemon so that it
# runs the new binary, and does nothing if the daemon is stopped.
#
# Called by dpkg as "configure [<previous version>]" (a previous version means upgrade) and by rpm with $1 = 1
# (install) or 2 (upgrade). Same structure as postinstall.sh of the portholed package.
#
# /etc/porthole/tunnels.yaml is not a package file: dpkg creates it here from the example if it does not exist, and
# never touches an existing one (as a conffile it made a non-interactive upgrade fail whenever the example changed).
# rpm does this in client-posttrans.sh. Upgrading from a version that shipped it as a conffile: dpkg leaves such an
# obsolete conffile on disk (and deletes it only on purge), so the file is kept.
set -e

case "$1" in
configure)
  if [ -n "${2:-}" ]; then action=upgrade; else action=install; fi
  tunnels=/etc/porthole/tunnels.yaml
  example=/usr/share/porthole/tunnels.example.yaml
  if [ ! -e "$tunnels" ] && [ -f "$example" ]; then
    # Readable by root and by the daemon user only. Without the group (removed by hand) keep going: the package is
    # installed, and the operator can create the file.
    install -m 0640 -o root -g porthole-client "$example" "$tunnels" ||
      echo "porthole: could not create $tunnels; copy $example there" >&2
  fi
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
