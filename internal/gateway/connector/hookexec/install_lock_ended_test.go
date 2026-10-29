// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/procidentity"
)

// endedChild starts a process that exits at once and is not reaped until the
// test ends: a zombie on Linux and macOS, a process object this test's
// handle keeps on Windows. It returns its pid and its identity (empty when
// the system no longer says).
func endedChild(t *testing.T) (int, string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(self, "-test.run=^$")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Wait() })
	pid := child.Process.Pid
	identity, _ := procidentity.Of(pid)
	for deadline := time.Now().Add(20 * time.Second); !procidentity.Ended(pid); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("pid %d never read as ended", pid)
		}
	}
	if identity == "" {
		identity, _ = procidentity.Of(pid)
	}
	return pid, identity
}

// oss-outage-open round l loop 1 (P2): a zombie installer kept its pid and
// its start, so its lock read as held for good: a strict or explicitly closed
// account was blocked even with the gateway answering. A lock whose owner
// has exited is no lock, with its proc-start record or without one.
func TestInstallLockOfAnEndedInstallerIsNoLock(t *testing.T) {
	pid, identity := endedChild(t)
	for _, record := range []bool{true, false} {
		t.Run("proc-start record "+strconv.FormatBool(record), func(t *testing.T) {
			home := t.TempDir()
			lock := filepath.Join(home, ".install.lock")
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(lock, "pid"), []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if record && identity != "" {
				if err := os.WriteFile(filepath.Join(lock, InstallLockIdentityName), []byte(identity+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if InstallLockHeld(home) {
				t.Fatalf("the lock of exited, unreaped installer pid %d holds", pid)
			}
			opts := Options{Home: home, FailMode: "open"}
			if got := closeDuringInstall(&opts, "open"); got == "closed" {
				t.Fatalf("closeDuringInstall = %q under the lock of an exited installer", got)
			}
		})
	}
}
