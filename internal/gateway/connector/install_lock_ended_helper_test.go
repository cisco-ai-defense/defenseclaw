// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/procidentity"
)

// endedInstallerPid starts a process that exits at once and is not reaped
// until the test ends (a zombie on Linux and macOS; on Windows a process
// object this test's handle keeps). It returns its pid and its identity
// (empty when the system no longer says).
func endedInstallerPid(t *testing.T) (string, string) {
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
	return strconv.Itoa(pid), identity
}
