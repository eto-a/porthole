// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package localapi

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestNotifyUnset(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	ok, err := Notify(NotifyReady)
	if ok || err != nil {
		t.Errorf("Notify without NOTIFY_SOCKET = %v, %v; want false, nil", ok, err)
	}
}

func TestNotifyWindowsNoop(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	t.Setenv("NOTIFY_SOCKET", filepath.Join(shortDir(t), "n.sock"))
	ok, err := Notify(NotifyReady)
	if ok || err != nil {
		t.Errorf("Notify on Windows = %v, %v; want false, nil", ok, err)
	}
}
