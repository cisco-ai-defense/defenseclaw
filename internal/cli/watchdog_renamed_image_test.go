// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"testing"
)

// GAP-1833: an upgrade renamed the running gateway aside, and the old
// watchdog it ran became unstoppable.
func TestWatchdogImageRenamedAsideFollowsTheInstallerRename(t *testing.T) {
	dir := t.TempDir()
	recorded := filepath.Join(dir, "defenseclaw-gateway.exe")
	cases := []struct {
		image string
		want  bool
	}{
		{recorded + ".old-20261002T193845029", true},
		{recorded, false},
		{recorded + ".old-", false},
		{recorded + ".old-20261002T19384502x", false},
		{recorded + ".bak-20261002T193845029", false},
		{filepath.Join(dir, "other.exe.old-20261002T193845029"), false},
		{filepath.Join(t.TempDir(), "defenseclaw-gateway.exe.old-20261002T193845029"), false},
	}
	for _, tc := range cases {
		if got := watchdogImageRenamedAside(tc.image, recorded); got != tc.want {
			t.Errorf("watchdogImageRenamedAside(%q) = %v, want %v", tc.image, got, tc.want)
		}
	}
	if watchdogImageRenamedAside(recorded+".old-20261002T193845029", "") {
		t.Error("an empty recorded executable must never match")
	}
}
