#!/bin/sh
# Post-transaction script of the portholed .rpm package (the .deb package does the same in postinstall.sh).
#
# Creates /etc/porthole/portholed.yaml from the shipped example if it does not exist; an existing file is never
# touched. It is not a package file (see .goreleaser.yaml), and it has to run after the old package is removed: when
# upgrading from a version that shipped the file as %config, rpm deletes it (unchanged) or renames it to
# portholed.yaml.rpmsave (edited) after the new package's %post. An .rpmsave left behind that way is restored instead
# of the example.
set -e

f=/etc/porthole/portholed.yaml
example=/usr/share/porthole/portholed.example.yaml

if [ ! -e "$f" ]; then
  if [ -f "$f.rpmsave" ]; then
    mv "$f.rpmsave" "$f"
  elif [ -f "$example" ]; then
    # Readable by root and by the service user only. Without the group (removed by hand) keep going: the package is
    # installed, and the operator can create the file.
    install -m 0640 -o root -g porthole "$example" "$f" ||
      echo "portholed: could not create $f; copy $example there" >&2
  fi
fi

exit 0
