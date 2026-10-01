#!/usr/bin/env bash
# Upgrade test of the portholed and porthole .deb packages; runs as root inside a Debian or Ubuntu container.
#
# usage: upgrade-deb.sh <dir with the old .deb files> <dir with the new .deb files>
#
# Every apt-get call has stdin on /dev/null, like an unattended upgrade: a dpkg conffile prompt would fail it with
# "end of file on stdin at conffile prompt". The old packages (v0.3.0-alpha.2) ship the two configuration files as
# conffiles; the new ones create them in postinst. Run through packaging/test/run-in-container.sh.
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=packaging/test/lib.sh
. "$here/lib.sh"

old=${1:?usage: upgrade-deb.sh <old dir> <new dir>}
new=${2:?usage: upgrade-deb.sh <old dir> <new dir>}
export DEBIAN_FRONTEND=noninteractive

srv_old=$(exactly_one "$old/portholed_*_linux_amd64.deb") || { echo "no single old portholed .deb in $old"; exit 2; }
cli_old=$(exactly_one "$old/porthole_*_linux_amd64.deb") || { echo "no single old porthole .deb in $old"; exit 2; }
srv_new=$(exactly_one "$new/portholed_*_linux_amd64.deb") || { echo "no single new portholed .deb in $new"; exit 2; }
cli_new=$(exactly_one "$new/porthole_*_linux_amd64.deb") || { echo "no single new porthole .deb in $new"; exit 2; }

# install_debs <files...>: unattended install; the output goes to a log, the exit status is the result.
install_debs() { apt-get install -y "$@" </dev/null >/tmp/apt.log 2>&1; }
remove_all() { apt-get remove -y portholed porthole </dev/null >/tmp/apt.log 2>&1; }
purge_all() { apt-get purge -y portholed porthole </dev/null >/tmp/apt.log 2>&1; }
conffile_of() { dpkg-query -W -f='${Conffiles}\n' "$1" | grep -q "$2"; }
# After an upgrade from a version that shipped the file as a conffile, dpkg keeps the entry marked "obsolete" (the
# file stays on disk and is deleted on purge), so only a live entry counts.
not_conffile_of() { ! dpkg-query -W -f='${Conffiles}\n' "$1" | grep "$2" | grep -vq obsolete; }

installed_ok() {
  check "$1: both configuration files exist" files_exist "$srv_conf" "$cli_conf"
  check "$1: both examples are installed" files_exist "$srv_example" "$cli_example"
  check "$1: portholed.yaml is not a live conffile any more" not_conffile_of portholed portholed.yaml
  check "$1: tunnels.yaml is not a live conffile any more" not_conffile_of porthole tunnels.yaml
}

purged_clean() {
  check "$1: purge exits 0" purge_all
  check "$1: purge removed both configuration files" none_exist "$srv_conf" "$cli_conf"
  check "$1: purge removed /etc/porthole" none_exist /etc/porthole
  check "$1: purge removed /var/lib/porthole" none_exist /var/lib/porthole
  check "$1: purge removed the users and groups" users_gone
}

# newer_copy <deb>: a copy with a higher version whose example file differs, in /tmp/repack.
newer_copy() {
  local b
  b=$(basename "$1" .deb)
  rm -rf "/tmp/repack/$b"
  mkdir -p /tmp/repack
  dpkg-deb -R "$1" "/tmp/repack/$b" || return 1
  sed -i 's/^Version: .*/&.1/' "/tmp/repack/$b/DEBIAN/control"
  echo '# CHANGED-EXAMPLE' >>"$(find "/tmp/repack/$b/usr/share/porthole" -name '*.example.yaml')"
  dpkg-deb -b "/tmp/repack/$b" "/tmp/repack/$b.deb" >/dev/null
}
changed_example() { grep -q CHANGED-EXAMPLE "$1"; }

scenario "A. clean install of the new packages"
check "A: install exits 0" install_debs "$srv_new" "$cli_new"
installed_ok A
check "A: portholed.yaml is root:porthole 0640" mode_is "$srv_conf" "640 root:porthole"
check "A: tunnels.yaml is root:porthole-client 0640" mode_is "$cli_conf" "640 root:porthole-client"
check "A: portholed.yaml equals the example" same_as "$srv_conf" "$srv_example"
check "A: tunnels.yaml equals the example" same_as "$cli_conf" "$cli_example"

scenario "B. edits survive an upgrade whose example differs (repacked copy with a higher version)"
edit_all
check "B: repack portholed" newer_copy "$srv_new"
check "B: repack porthole" newer_copy "$cli_new"
check "B: upgrade exits 0" install_debs /tmp/repack/portholed_*.deb /tmp/repack/porthole_*.deb
check "B: portholed.yaml keeps the edit" edited "$srv_conf"
check "B: tunnels.yaml keeps the edit" edited "$cli_conf"
check "B: portholed example was updated" changed_example "$srv_example"
check "B: tunnels example was updated" changed_example "$cli_example"

scenario "C. remove keeps the files and users, purge deletes them"
check "C: remove exits 0" remove_all
check "C: remove keeps both edited files" bash -c "grep -q '^# MYEDIT\$' $srv_conf && grep -q '^# MYEDIT\$' $cli_conf"
check "C: remove keeps the users and groups" users_exist
mkdir -p /var/lib/porthole && echo data >/var/lib/porthole/porthole.db
purged_clean C

scenario "D. upgrade from the published packages, both files edited (the failing case before)"
check "D: old install exits 0" install_debs "$srv_old" "$cli_old"
check "D: old portholed owns portholed.yaml as a conffile" conffile_of portholed portholed.yaml
check "D: old porthole owns tunnels.yaml as a conffile" conffile_of porthole tunnels.yaml
edit_all
echo data >/var/lib/porthole/porthole.db
check "D: upgrade exits 0 without a terminal" install_debs "$srv_new" "$cli_new"
check "D: portholed.yaml keeps the edit" edited "$srv_conf"
check "D: tunnels.yaml keeps the edit" edited "$cli_conf"
check "D: the data directory is untouched" grep -q data /var/lib/porthole/porthole.db
installed_ok D
purged_clean D

scenario "E. upgrade from the published packages, files unchanged"
check "E: old install exits 0" install_debs "$srv_old" "$cli_old"
check "E: upgrade exits 0 without a terminal" install_debs "$srv_new" "$cli_new"
installed_ok E
purged_clean E

finish
