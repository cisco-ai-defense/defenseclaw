// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"testing"
)

func TestRegistrationArchivePossibleReachUsesRegisteredFolder(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	settingsDir := filepath.Join(home, ".claude")
	names := []string{settingsDir, filepath.Join(settingsDir, "settings.json")}
	for _, tc := range []struct {
		command string
		want    string
	}{
		{"tar -xf bundle.tar -C " + root, ""},
		{"unzip bundle.zip -d " + home, ""},
		{"tar -xf bundle.tar -C " + settingsDir, settingsDir},
		{"unzip bundle.zip -d " + settingsDir, settingsDir},
	} {
		if got := RegistrationArchivePossibleReach(tc.command, root, home, names); got != tc.want {
			t.Errorf("%q: reached %q, want %q", tc.command, got, tc.want)
		}
	}
}
