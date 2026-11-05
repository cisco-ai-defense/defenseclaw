// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hermespath

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGAP0540AccountHomeRescansAfterVersionProbe(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	t.Cleanup(OverrideAccountEnvironmentForTest(root))
	proc := filepath.Join(root, "proc", "7501")
	if err := os.MkdirAll(proc, 0o755); err != nil {
		t.Fatal(err)
	}
	writeEnvironment := func(value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(proc, "environ"), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	scratch := filepath.Join(t.TempDir(), "dc-agent-probe-1")
	writeEnvironment("HOME=" + home + "\x00HERMES_HOME=" + scratch + "\x00TMPDIR=" + scratch +
		"\x00DC_AGENT_VERSION_PROBE=hermes\x00")
	previous := waitManagedHermesVersion
	called := false
	waitManagedHermesVersion = func(_ string, pid int, accountHome string, _ time.Duration) bool {
		if pid != 7501 || accountHome != home {
			t.Fatalf("probe wait received pid %d and home %q", pid, accountHome)
		}
		called = true
		if err := os.RemoveAll(proc); err != nil {
			t.Fatal(err)
		}
		return true
	}
	t.Cleanup(func() { waitManagedHermesVersion = previous })
	if err := VerifyAccountHome(home, filepath.Join(home, ".hermes"), time.Time{}); err != nil {
		t.Fatalf("completed version process remained in the account scan: %v", err)
	}
	if !called {
		t.Fatal("account scan did not check the version process")
	}
	if err := os.MkdirAll(proc, 0o755); err != nil {
		t.Fatal(err)
	}
	writeEnvironment("HOME=" + home + "\x00HERMES_HOME=" + filepath.Join(t.TempDir(), "other") + "\x00")
	if err := VerifyAccountHome(home, filepath.Join(home, ".hermes"), time.Time{}); err == nil {
		t.Fatal("a running process with another home was not reported")
	}
}
