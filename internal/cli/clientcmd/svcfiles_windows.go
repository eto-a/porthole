// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import "github.com/eto-a/porthole/internal/service"

// handToServiceAccount makes Administrators the owner of the files an elevated administrator just wrote into
// %ProgramData%\porthole: they would otherwise be owned by that user's SID, which the service (LocalSystem) cannot
// tell from an ordinary user's when it checks its directory.
func handToServiceAccount(config, tunnels string) (bool, error) {
	changed := false
	for _, p := range []string{config, tunnels} {
		if p == "" {
			continue
		}
		if err := service.SetAdminOwner(p); err != nil {
			return changed, err
		}
		changed = true
	}
	return changed, nil
}
