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

// A version process can finish between the first /proc scan and lineage proof.
func TestGAP0540ExitedProbeDoesNotRemainAccountEvidence(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	t.Cleanup(OverrideAccountEnvironmentForTest(root))
	proc := filepath.Join(root, "proc", "7501")
	if err := os.MkdirAll(proc, 0o755); err != nil {
		t.Fatal(err)
	}
	scratch := filepath.Join(t.TempDir(), "dc-agent-probe-1")
	env := "HOME=" + home + "\x00HERMES_HOME=" + scratch + "\x00TMPDIR=" + scratch +
		"\x00DC_AGENT_VERSION_PROBE=hermes\x00"
	if err := os.WriteFile(filepath.Join(proc, "environ"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := waitManagedHermesVersion
	called := false
	waitManagedHermesVersion = func(_ string, pid int, accountHome string, _ time.Duration) bool {
		if pid != 7501 || accountHome != home {
			t.Fatalf("unexpected probe pid or account home")
		}
		called = true
		if err := os.RemoveAll(proc); err != nil {
			t.Fatal(err)
		}
		// The real provenance check returns false once the PID is gone.
		return false
	}
	t.Cleanup(func() { waitManagedHermesVersion = previous })
	if err := VerifyAccountHome(home, filepath.Join(home, ".hermes"), time.Time{}); err != nil {
		t.Errorf("finished probe left stale account-home evidence: %v", err)
	}
	if !called {
		t.Fatal("the version probe was not considered")
	}
}
