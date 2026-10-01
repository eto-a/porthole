#!/bin/sh
# Pre-install script of the porthole (client) .deb and .rpm packages.
#
# Creates the "porthole-client" system group and user that the porthole.service daemon runs as. It runs before the
# files are unpacked, because /etc/porthole/tunnels.yaml is shipped as root:porthole-client and the group has to exist
# by then (the rpm packaging guidelines put user creation in %pre for the same reason). The user has no login shell and
# no home directory. It is deliberately not the server's "porthole" user: a machine may run both, and the client must
# not be able to read the server's database. The group also controls access to the daemon's socket (see the unit).
#
# Called by dpkg as "install" or "upgrade <old version>" and by rpm with $1 = 1 (install) or 2 (upgrade); creating the
# user is idempotent, so the distinction does not matter. Structure follows postinstall.sh of the portholed package.
set -e

user=porthole-client
group=porthole-client

case "$1" in
install | upgrade | 1 | 2) ;;
*) exit 0 ;;
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
    --home-dir /nonexistent \
    --shell "$nologin" \
    --comment "porthole tunnel client" \
    "$user"
fi

exit 0
