// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"path/filepath"
	"runtime"
	"testing"
)

// GAP-0122: a root guardian acting for a Linux or macOS user resolves that
// user's ~/.hermes/config.yaml, not its own home's; in the process's own
// home HERMES_HOME still applies.
func TestHermesConfigPathFollowsTheTargetUsersHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows resolves LocalAppData; covered by the Windows Hermes tests")
	}
	previousOverride := HermesConfigPathOverride
	HermesConfigPathOverride = ""
	t.Cleanup(func() { HermesConfigPathOverride = previousOverride })
	own := t.TempDir()
	target := t.TempDir()
	custom := t.TempDir()
	t.Setenv("HOME", own)
	t.Setenv("HERMES_HOME", custom)

	resolve := func(home string) string {
		t.Helper()
		var got string
		if err := WithUserHomeDir(home, func() error {
			got = hermesConfigPath(SetupOpts{})
			return nil
		}); err != nil {
			t.Fatalf("WithUserHomeDir(%s): %v", home, err)
		}
		return got
	}
	if got, want := resolve(target), filepath.Join(target, ".hermes", "config.yaml"); got != want {
		t.Fatalf("another user's Hermes config = %q, want %q (not the process home or its HERMES_HOME)", got, want)
	}
	if got, want := resolve(own), filepath.Join(custom, "config.yaml"); got != want {
		t.Fatalf("own Hermes config = %q, want %q (HERMES_HOME applies in the process's own home)", got, want)
	}
	if got, want := hermesConfigPath(SetupOpts{}), filepath.Join(custom, "config.yaml"); got != want {
		t.Fatalf("Hermes config without a home binding = %q, want %q", got, want)
	}
	if isProcessUserHome("") || !isProcessUserHome(own+string(filepath.Separator)) {
		t.Fatal("isProcessUserHome must reject an empty home and accept the process home with a trailing separator")
	}
}
