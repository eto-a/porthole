#!/bin/sh
# Post-install script of the portholed .deb and .rpm packages.
#
# Creates the "porthole" system user and the data directory. It deliberately does NOT enable or start the service:
# the shipped /etc/porthole/portholed.yaml is only an example and must be edited first.
#
# Called by dpkg as "configure [<previous version>]" (a previous version means upgrade) and by rpm with $1 = 1
# (install) or 2 (upgrade). Structure follows the Caddy packaging scripts
# (https://github.com/caddyserver/dist, scripts/postinstall.sh); the install/upgrade split follows zrok
# (https://github.com/openziti/zrok, nfpm/postinstall-controller.bash).
set -e

user=porthole
group=porthole
home=/var/lib/porthole

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

if ! getent group "$group" >/dev/null 2>&1; then
  groupadd --system "$group"
fi

if ! getent passwd "$user" >/dev/null 2>&1; then
  nologin=/usr/sbin/nologin
  [ -x "$nologin" ] || nologin=/sbin/nologin
  [ -x "$nologin" ] || nologin=/bin/false
  useradd --system \
    --gid "$group" \
    --no-create-home \
    --home-dir "$home" \
    --shell "$nologin" \
    --comment "porthole tunnel server" \
    "$user"
fi

# The SQLite database (token hashes) lives here; keep it private to the service user.
install -d -o "$user" -g "$group" -m 0750 "$home"

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
  if [ "$action" = upgrade ]; then
    # Restart a running server so it runs the new binary; do nothing if it is stopped.
    systemctl try-restart portholed.service >/dev/null 2>&1 || true
  fi
fi

if [ "$action" = install ]; then
  cat <<'MSG'

portholed is installed but NOT started. Next steps:
  1. Edit /etc/porthole/portholed.yaml (set `domain` and the TLS certificate paths).
  2. sudo systemctl enable --now portholed
  3. sudo -u porthole portholed token create --name home
     (run it as the porthole user so the database stays readable by the service)

MSG
fi

exit 0
