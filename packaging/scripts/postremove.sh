#!/bin/sh
# Post-remove script of the portholed .deb and .rpm packages.
#
# Removing the package keeps the configuration, the data directory (the token database) and the system user.
# Only `apt purge portholed` (dpkg "purge") deletes the data directory, the user and the (empty) config directory,
# like the Caddy package does (caddyserver/dist scripts/postremove.sh). rpm has no purge: nothing is deleted there.
# dpkg itself removes the unchanged and the modified conffile /etc/porthole/portholed.yaml on purge.
set -e

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

if [ "$1" = purge ]; then
  rm -rf /var/lib/porthole
  if getent passwd porthole >/dev/null 2>&1; then
    userdel porthole >/dev/null 2>&1 || true
  fi
  if getent group porthole >/dev/null 2>&1; then
    groupdel porthole >/dev/null 2>&1 || true
  fi
  # Not rm -rf: certificates or keys the operator put under /etc/porthole/tls are theirs.
  rmdir /etc/porthole >/dev/null 2>&1 || true
fi

exit 0
