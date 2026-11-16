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

func TestGAP0540SequentialVersionProbesDoNotBlockAccountVerify(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	t.Cleanup(OverrideAccountEnvironmentForTest(root))
	scratch, err := os.MkdirTemp(t.TempDir(), "dc-agent-probe-")
	if err != nil {
		t.Fatal(err)
	}
	retryScratch, err := os.MkdirTemp(t.TempDir(), "dc-agent-probe-")
	if err != nil {
		t.Fatal(err)
	}
	writeProbe := func(pid string) {
		t.Helper()
		proc := filepath.Join(root, "proc", pid)
		if err := os.MkdirAll(proc, 0o755); err != nil {
			t.Fatal(err)
		}
		value := scratch
		if pid == "8302" {
			value = retryScratch
		}
		env := []byte("HOME=" + home + "\x00HERMES_HOME=" + value + "\x00TMPDIR=" + value +
			"\x00DC_AGENT_VERSION_PROBE=hermes\x00")
		if err := os.WriteFile(filepath.Join(proc, "environ"), env, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeProbe("8301")
	previous := waitManagedHermesVersion
	called := map[int]bool{}
	retryDone := make(chan struct{})
	var retryErr error
	waitManagedHermesVersion = func(_ string, pid int, accountHome string, _ time.Duration) bool {
		if accountHome != home {
			t.Fatalf("wrong account home")
		}
		called[pid] = true
		switch pid {
		case 8301:
			if err := os.RemoveAll(filepath.Join(root, "proc", "8301")); err != nil {
				t.Fatal(err)
			}
			writeProbe("8302")
			go func() {
				time.Sleep(500 * time.Millisecond)
				retryErr = os.RemoveAll(filepath.Join(root, "proc", "8302"))
				close(retryDone)
			}()
		case 8302:
			<-retryDone
			return retryErr == nil
		default:
			t.Fatalf("unexpected version probe pid %d", pid)
		}
		return true
	}
	t.Cleanup(func() { waitManagedHermesVersion = previous })
	err = VerifyAccountHome(home, filepath.Join(home, ".hermes"), time.Time{})
	if !called[8301] {
		t.Fatal("first version probe was not checked")
	}
	<-retryDone
	if retryErr != nil {
		t.Fatal(retryErr)
	}
	if err != nil {
		t.Errorf("second legitimate version probe blocked account verification: %v", err)
	}
	if !called[8302] {
		t.Error("second legitimate version probe was not waited for")
	}
}
