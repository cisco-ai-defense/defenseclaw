// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"path/filepath"
	"testing"
)

// Devin Desktop is found at its installers' default locations; Linux has no
// probe yet, and other connectors have no desktop surface.
func TestDevinDesktopSurfaceProbes(t *testing.T) {
	home := filepath.FromSlash("/home/u")
	for _, tc := range []struct {
		goos, connector, installed, want string
	}{
		{"darwin", "devin", "/Applications/Devin.app/Contents/Info.plist", "/Applications/Devin.app/Contents/Info.plist"},
		{"windows", "devin", "/home/u/AppData/Local/Programs/Devin/Devin.exe", "/home/u/AppData/Local/Programs/Devin/Devin.exe"},
		{"windows", "devin", "/pf/Devin/Devin.exe", "/pf/Devin/Devin.exe"},
		{"linux", "devin", "/usr/share/devin/devin", ""},
		{"darwin", "codex", "/Applications/Devin.app/Contents/Info.plist", ""},
	} {
		installed := filepath.FromSlash(tc.installed)
		got := desktopSurfaceInstalled(tc.goos, home, tc.connector, filepath.FromSlash("/pf"), func(path string) bool { return path == installed })
		if want := filepath.FromSlash(tc.want); got != want {
			t.Errorf("%s %s: got %q, want %q", tc.goos, tc.connector, got, want)
		}
	}
}
