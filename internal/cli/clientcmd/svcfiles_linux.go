// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package clientcmd

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"

	"github.com/eto-a/porthole/internal/service"
)

// handToServiceAccount gives the files of /etc/porthole to the account the system unit runs as (porthole-client), as
// the deb and rpm packages do: config.yaml (it holds the token) becomes porthole-client:porthole-client 0600, and
// tunnels.yaml root:porthole-client 0640. An empty path is skipped. It reports whether anything changed, and does
// nothing (no error) while the account does not exist yet (the first `service install` creates it).
func handToServiceAccount(config, tunnels string) (bool, error) {
	u, err := user.Lookup(service.ClientUser)
	if err != nil {
		var unknown user.UnknownUserError
		if errors.As(err, &unknown) {
			return false, nil
		}
		return false, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return false, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return false, err
	}
	changed := false
	for _, f := range []struct {
		path string
		uid  int // -1: keep the owner
		mode os.FileMode
	}{{config, uid, 0o600}, {tunnels, -1, 0o640}} {
		if f.path == "" {
			continue
		}
		fi, err := os.Stat(f.path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return changed, err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		if int(st.Gid) == gid && (f.uid == -1 || int(st.Uid) == f.uid) && fi.Mode().Perm() == f.mode {
			continue
		}
		if err := os.Chown(f.path, f.uid, gid); err != nil {
			return changed, fmt.Errorf("chown %s: %w", f.path, err)
		}
		if err := os.Chmod(f.path, f.mode); err != nil {
			return changed, fmt.Errorf("chmod %s: %w", f.path, err)
		}
		changed = true
	}
	return changed, nil
}
