// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
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

// pid1RecordedExecutable is an executable path the record of PID 1 (another
// account's process here) would need for its identity to verify: on Linux,
// /proc/1/exe is unreadable, so a path whose base name is /proc/1/comm; on
// macOS, the program ps names.
func pid1RecordedExecutable(t *testing.T) string {
	t.Helper()
	switch runtime.GOOS {
	case "linux":
		raw, err := os.ReadFile("/proc/1/comm")
		if err != nil || strings.TrimSpace(string(raw)) == "" {
			t.Skipf("/proc/1/comm unavailable: %v", err)
		}
		if _, err := os.Readlink("/proc/1/exe"); err == nil {
			t.Skip("/proc/1/exe is readable here; the comm fallback is not reached")
		}
		return "/opt/defenseclaw/" + strings.TrimSpace(string(raw))
	case "darwin":
		executable, err := processExecutableDarwin(1)
		if err != nil || executable == "" {
			t.Skipf("ps cannot name PID 1: %v", err)
		}
		return executable
	default:
		t.Skip("no process identity for another account's process on " + runtime.GOOS)
		return ""
	}
}

// Another account's process is this home's gateway only on a record that
// carries its kernel start identity and names this data directory. Records
// without either keep the answer they had before EPERM read as alive (not
// running, record removed): the review of PR #1426 showed that a record with
// no start identity made any root process with a matching name "running".
func TestIsRunningNeedsStartIdentityAndDataDirForAnotherAccountsProcess(t *testing.T) {
	if os.Geteuid() == 0 || processSignalable(1) {
		t.Skip("needs a live process of another account (PID 1 is this account's here)")
	}
	t.Setenv(EnvDaemon, "")
	executable := pid1RecordedExecutable(t)
	identity, err := processStartIdentity(1)
	if err != nil || identity == "" {
		t.Skipf("start identity of PID 1 unavailable: identity=%q err=%v", identity, err)
	}
	dir := t.TempDir()
	d := New(dir)
	write := func(info pidInfo) {
		t.Helper()
		data, err := json.Marshal(info)
		if err != nil {
			t.Fatal(err)
		}
		if err := safefile.WritePrivate(d.pidFile, data); err != nil {
			t.Fatal(err)
		}
	}

	// The strong record verifies: name and kernel start identity.
	strong := pidInfo{PID: 1, Executable: executable, DataDir: dir, StartIdentity: identity}
	write(strong)
	if !d.recordBindsThisHome(strong) || !d.verifyExecutable(strong) {
		t.Fatal("a record with start identity and this data dir must reach the identity checks")
	}
	if running, pid := d.IsRunning(); !running || pid != 1 {
		t.Fatalf("IsRunning(strong record) = (%v, %d), want (true, 1)", running, pid)
	}

	other := t.TempDir()
	for name, info := range map[string]pidInfo{
		"no start identity":    {PID: 1, Executable: executable, DataDir: dir},
		"blank start identity": {PID: 1, Executable: executable, DataDir: dir, StartIdentity: "  "},
		"no data dir":          {PID: 1, Executable: executable, StartIdentity: identity},
		"another data dir":     {PID: 1, Executable: executable, DataDir: other, StartIdentity: identity},
	} {
		write(info)
		if d.recordBindsThisHome(info) {
			t.Errorf("%s: recordBindsThisHome = true", name)
		}
		if runtime.GOOS == "linux" && d.verifyExecutable(info) {
			t.Errorf("%s: /proc/1/comm accepted as the executable", name)
		}
		if running, pid := d.IsRunning(); running || pid != 0 {
			t.Errorf("%s: IsRunning = (%v, %d), want (false, 0)", name, running, pid)
		}
		if _, err := os.Stat(d.pidFile); !os.IsNotExist(err) {
			t.Errorf("%s: the weak record of another account's process was kept (stat err %v)", name, err)
		}
	}
}
