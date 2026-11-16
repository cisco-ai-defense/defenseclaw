// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestNativeHookGatewayReadsOnlyItsOwnAccountHome: the gateway binary the
// shell hook tests run answers hook-outage-mode from the account home its
// test process gave it, never from the build account's real ~/.defenseclaw.
// An install lock another test or build left there for a moment closed the
// outage of TestShellHookBehaviourMatchesGolden's unreachable cases at random
// (rel-1-0-6:GAP-0345). Not parallel: it puts a lock in the shared fixture.
func TestNativeHookGatewayReadsOnlyItsOwnAccountHome(t *testing.T) {
	home := t.TempDir()
	installNativeGatewayForHookTest(t, home)
	data := filepath.Join(home, ".defenseclaw")
	writeOutageTierConfig(t, data, outageDefaultTierConfig)
	mode := func() string {
		t.Helper()
		cmd := exec.Command(filepath.Join(home, ".local", "bin", "defenseclaw-gateway"),
			"hook-outage-mode", "--connector", "claudecode", "--hook-dir", filepath.Join(data, "hooks"))
		cmd.Env = append(sanitizedTestEnv(), "HOME="+home)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("hook-outage-mode: %v", err)
		}
		return strings.TrimSpace(string(out))
	}
	if got := mode(); got != "open" {
		t.Fatalf("default tier outage mode = %q, want open", got)
	}
	account := filepath.Join(nativeGatewayForHookTests.accountHome, ".defenseclaw")
	if err := os.MkdirAll(account, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(account) })
	if err := os.WriteFile(filepath.Join(account, ".install.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := mode(); got != "closed" {
		t.Fatalf("outage mode with the account's install lock = %q, want closed: the binary did not read its own account home", got)
	}
}
