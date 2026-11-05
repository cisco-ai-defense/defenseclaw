// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package daemon

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// PID 1 belongs to root: kill(2) answers EPERM, and the process exists. The
// gateway the macOS app's privileged helper starts for this home is such a
// process; reading EPERM as "gone" removed its PID record (status then said
// "no gateway started for <home> is running").
func TestProcessExistsForAnotherAccountsProcess(t *testing.T) {
	if os.Geteuid() == 0 || processSignalable(1) {
		t.Skip("needs a live process of another account (PID 1 is this account's here)")
	}
	if !processExists(1) {
		t.Fatal("PID 1 is alive; EPERM must not read as gone")
	}
	if processSignalable(1) {
		t.Fatal("PID 1 is root's; this account must not be able to signal it")
	}
	if !processSignalable(os.Getpid()) {
		t.Fatal("this process is this account's to signal")
	}
}

// A live process this account cannot signal keeps its PID record even when
// its identity does not verify: it is not stale evidence this account may
// discard.
func TestIsRunningKeepsRecordOfAnotherAccountsProcess(t *testing.T) {
	if os.Geteuid() == 0 || processSignalable(1) {
		t.Skip("needs a live process of another account (PID 1 is this account's here)")
	}
	t.Setenv(EnvDaemon, "")
	d := New(t.TempDir())
	if err := d.writePIDInfo(1, "/not/the/recorded/gateway", "0.000001"); err != nil {
		t.Fatal(err)
	}
	if running, pid := d.IsRunning(); running || pid != 0 {
		t.Fatalf("IsRunning = (%v, %d), want an unverified process reported as not running", running, pid)
	}
	if _, err := os.Stat(d.pidFile); err != nil {
		t.Fatalf("the record of a live process of another account was removed: %v", err)
	}
}

// /proc/<pid>/comm holds the first 15 bytes of the program's base name; the
// recorded executable is matched by that prefix and nothing else.
func TestLinuxCommNamesExecutable(t *testing.T) {
	root := t.TempDir()
	write := func(pid int, comm string) {
		dir := filepath.Join(root, strconv.Itoa(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The kernel keeps 15 bytes of "defenseclaw-gateway".
	write(10, "defenseclaw-gat")
	write(11, "bash")
	write(12, "")
	cases := []struct {
		pid        int
		executable string
		want       bool
	}{
		{10, "/Library/PrivilegedHelperTools/DefenseClawMacGatewayAdmin/uid-501/defenseclaw-gateway", true},
		{10, "/usr/local/bin/defenseclaw-gateway", true},
		{10, "/usr/local/bin/defenseclaw-gat", true},
		{10, "", false},
		{10, "/", false},
		{10, "/usr/bin/other", false},
		{11, "/usr/local/bin/defenseclaw-gateway", false},
		{12, "/usr/local/bin/defenseclaw-gateway", false},
		{13, "/usr/local/bin/defenseclaw-gateway", false},
	}
	for _, tc := range cases {
		if got := linuxCommNamesExecutable(root, tc.pid, tc.executable); got != tc.want {
			t.Errorf("linuxCommNamesExecutable(%d, %q) = %v, want %v", tc.pid, tc.executable, got, tc.want)
		}
	}
}
