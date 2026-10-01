#!/bin/sh
# Post-remove script of the porthole (client) .deb and .rpm packages.
#
# Removing the package keeps the configuration (/etc/porthole/config.yaml, tunnels.yaml) and the system user. Only
# `apt purge porthole` (dpkg "purge") deletes the credentials the operator stored (config.yaml and token, which
# would otherwise stay behind owned by a group that no longer exists), the user and the group. rpm has no purge: nothing
# is deleted there. dpkg itself removes the shipped conffile tunnels.yaml on purge. The directory /etc/porthole is shared
# with the portholed package and is removed only when empty.
set -e

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

if [ "$1" = purge ]; then
  rm -f /etc/porthole/config.yaml /etc/porthole/token
  if getent passwd porthole-client >/dev/null 2>&1; then
    userdel porthole-client >/dev/null 2>&1 || true
  fi
  if getent group porthole-client >/dev/null 2>&1; then
    groupdel porthole-client >/dev/null 2>&1 || true
  fi
  # Not rm -rf: anything else the operator put under /etc/porthole is theirs.
  rmdir /etc/porthole >/dev/null 2>&1 || true
fi

exit 0
