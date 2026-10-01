#!/usr/bin/env bash
# Upgrade test of the portholed and porthole .rpm packages; runs as root inside a Fedora (or RHEL-like) container.
#
# usage: upgrade-rpm.sh <dir with the old .rpm files> <dir with the new .rpm files>
#
# The old packages (v0.3.0-alpha.2) ship the two configuration files as %config(noreplace); the new ones create them
# in posttrans, after rpm has deleted or renamed (to .rpmsave) the old files, and restore an .rpmsave. rpm has no
# purge: removal keeps the files. Run through packaging/test/run-in-container.sh.
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=packaging/test/lib.sh
. "$here/lib.sh"

old=${1:?usage: upgrade-rpm.sh <old dir> <new dir>}
new=${2:?usage: upgrade-rpm.sh <old dir> <new dir>}

srv_old=$(exactly_one "$old/portholed_*_linux_amd64.rpm") || { echo "no single old portholed .rpm in $old"; exit 2; }
cli_old=$(exactly_one "$old/porthole_*_linux_amd64.rpm") || { echo "no single old porthole .rpm in $old"; exit 2; }
srv_new=$(exactly_one "$new/portholed_*_linux_amd64.rpm") || { echo "no single new portholed .rpm in $new"; exit 2; }
cli_new=$(exactly_one "$new/porthole_*_linux_amd64.rpm") || { echo "no single new porthole .rpm in $new"; exit 2; }

# dnf resolves the shadow-utils dependency; stdin is /dev/null like in an unattended run.
install_rpms() { dnf install -y "$@" </dev/null >/tmp/dnf.log 2>&1; }
reinstall() { rpm -U --replacepkgs "$@" </dev/null; }
remove_all() { rpm -e portholed porthole; }
owned() { rpm -qf "$1"; }
not_owned() { ! rpm -qf "$1"; }
no_leftovers() { none_exist /etc/porthole/*.rpmsave /etc/porthole/*.rpmnew; }
# rpm has no purge: clean up by hand between scenarios.
reset() {
  remove_all >/dev/null 2>&1
  rm -rf /etc/porthole /var/lib/porthole
}

installed_ok() {
  check "$1: both configuration files exist" files_exist "$srv_conf" "$cli_conf"
  check "$1: both examples are installed" files_exist "$srv_example" "$cli_example"
  check "$1: portholed.yaml is not owned by a package" not_owned "$srv_conf"
  check "$1: tunnels.yaml is not owned by a package" not_owned "$cli_conf"
  check "$1: no .rpmsave or .rpmnew is left behind" no_leftovers
}

scenario "A. clean install of the new packages"
check "A: install exits 0" install_rpms "$srv_new" "$cli_new"
installed_ok A
check "A: portholed.yaml is root:porthole 0640" mode_is "$srv_conf" "640 root:porthole"
check "A: tunnels.yaml is root:porthole-client 0640" mode_is "$cli_conf" "640 root:porthole-client"
check "A: portholed.yaml equals the example" same_as "$srv_conf" "$srv_example"
check "A: tunnels.yaml equals the example" same_as "$cli_conf" "$cli_example"

scenario "B. reinstall of the same packages keeps the edits"
edit_all
check "B: reinstall exits 0" reinstall "$srv_new" "$cli_new"
check "B: portholed.yaml keeps the edit" edited "$srv_conf"
check "B: tunnels.yaml keeps the edit" edited "$cli_conf"

scenario "C. remove keeps the files and users"
check "C: remove exits 0" remove_all
check "C: remove keeps portholed.yaml" edited "$srv_conf"
check "C: remove keeps tunnels.yaml" edited "$cli_conf"
check "C: remove keeps the users and groups" users_exist
reset

scenario "D. upgrade from the published packages, both files edited (the .rpmsave case)"
check "D: old install exits 0" install_rpms "$srv_old" "$cli_old"
check "D: old portholed owns portholed.yaml" owned "$srv_conf"
check "D: old porthole owns tunnels.yaml" owned "$cli_conf"
edit_all
mkdir -p /var/lib/porthole && echo data >/var/lib/porthole/porthole.db
check "D: upgrade exits 0" install_rpms "$srv_new" "$cli_new"
check "D: portholed.yaml keeps the edit" edited "$srv_conf"
check "D: tunnels.yaml keeps the edit" edited "$cli_conf"
check "D: the data directory is untouched" grep -q data /var/lib/porthole/porthole.db
installed_ok D
reset

scenario "E. upgrade from the published packages, files unchanged"
check "E: old install exits 0" install_rpms "$srv_old" "$cli_old"
check "E: upgrade exits 0" install_rpms "$srv_new" "$cli_new"
installed_ok E
reset

finish
