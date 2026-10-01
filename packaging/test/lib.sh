# shellcheck shell=bash
# Helpers shared by upgrade-deb.sh and upgrade-rpm.sh (sourced; not executable on its own).
#
# Every check prints "ok" or "FAIL"; finish returns 1 if any check failed, so a script reports all failures at once.

fails=0
checks=0

srv_conf=/etc/porthole/portholed.yaml
cli_conf=/etc/porthole/tunnels.yaml
# The example paths are used by the scripts that source this file.
# shellcheck disable=SC2034
srv_example=/usr/share/porthole/portholed.example.yaml
# shellcheck disable=SC2034
cli_example=/usr/share/porthole/tunnels.example.yaml

scenario() { printf '\n== %s\n' "$1"; }

# check <description> <command or function...>: passes when it exits 0 (its output is discarded).
check() {
  local desc=$1
  shift
  checks=$((checks + 1))
  if "$@" >/dev/null 2>&1; then
    printf '  ok    %s\n' "$desc"
  else
    printf '  FAIL  %s\n' "$desc"
    fails=$((fails + 1))
  fi
}

# edit_all: the operator edits both configuration files (a marker line).
edit_all() { echo '# MYEDIT' >>"$srv_conf" && echo '# MYEDIT' >>"$cli_conf"; }

# edited <file>: the operator's edit is still in the file.
edited() { grep -q '^# MYEDIT$' "$1"; }

files_exist() {
  local f
  for f in "$@"; do [ -f "$f" ] || return 1; done
}

none_exist() {
  local f
  for f in "$@"; do [ ! -e "$f" ] || return 1; done
}

# mode_is <file> "<mode> <owner>:<group>"
mode_is() { [ "$(stat -c '%a %U:%G' "$1")" = "$2" ]; }

# same_as <file> <file>: identical content (sha256sum, because minimal images have no cmp).
same_as() { [ "$(sha256sum <"$1")" = "$(sha256sum <"$2")" ]; }

users_exist() { getent passwd porthole && getent passwd porthole-client && getent group porthole && getent group porthole-client; }

users_gone() { ! getent passwd porthole && ! getent passwd porthole-client && ! getent group porthole && ! getent group porthole-client; }

# exactly_one <glob>: prints the single file the glob matches; fails otherwise. The glob is expanded here, on purpose.
exactly_one() {
  local m
  # shellcheck disable=SC2206
  m=($1)
  [ "${#m[@]}" -eq 1 ] && [ -f "${m[0]}" ] && printf '%s\n' "${m[0]}"
}

finish() {
  printf '\n%d checks, %d failed\n' "$checks" "$fails"
  [ "$fails" -eq 0 ]
}
