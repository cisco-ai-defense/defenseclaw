// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// oss-outage-open review (round g, loop round 1), Windows: install.ps1 holds
// .install.lock in its DEFENSECLAW_HOME, the data root of the protected
// install state. A hook runtime whose data_dir is set apart from it, run by
// an agent with another USERPROFILE, HOME and DEFENSECLAW_HOME, closes its
// outage while that lock is held.
func TestPackagedWindowsHookOutageClosesWhileTheInstalledDataRootIsLocked(t *testing.T) {
	_, installed := stageTrustedNativeHookForTest(t, "open")
	data := filepath.Join(t.TempDir(), "custom-data")
	writeOutageNowConfig(t, data, "data_dir: "+data+"\n"+outageNowDefaultConfig)
	agent := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", agent)
	t.Setenv("DEFENSECLAW_CONFIG", "")
	t.Setenv("USERPROFILE", agent)
	t.Setenv("HOME", agent)
	oldAccount := outageAccountHome
	outageAccountHome = func() string { return "" }
	t.Cleanup(func() { outageAccountHome = oldAccount })

	if got := hookOutageFailModeNow("opencode", filepath.Join(data, "hooks")); got != "open" {
		t.Fatalf("no install: outage mode %q, want open", got)
	}
	if err := os.Mkdir(filepath.Join(installed, ".install.lock"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := hookOutageFailModeNow("opencode", filepath.Join(data, "hooks")); got != "closed" {
		t.Fatalf("install.ps1 holds the installed data root: outage mode %q, want closed", got)
	}
}
