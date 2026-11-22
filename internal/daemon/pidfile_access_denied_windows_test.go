// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package daemon

import (
	"encoding/json"
	"os"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// rel-1-0-10:GAP-1314, the process-inspection seam: OpenProcess access denied
// (a process this caller may not open) is alive and not signalable, and never
// on its own removes gateway.pid; ERROR_INVALID_PARAMETER (the kernel no
// longer knows the PID) is gone and removes it. This process stands in for
// the gateway, so the kernel process list still gives its creation time.
func TestIsRunningAccessDeniedKeepsPIDFile(t *testing.T) {
	pid := os.Getpid()
	identity, err := processStartIdentity(pid)
	if err != nil || identity == "" {
		t.Fatalf("processStartIdentity(self) = %q, %v", identity, err)
	}
	openErr := error(windows.ERROR_ACCESS_DENIED)
	prev := openProcessQuery
	openProcessQuery = func(p int) (windows.Handle, error) {
		if p == pid {
			return 0, openErr
		}
		return prev(p)
	}
	t.Cleanup(func() { openProcessQuery = prev })

	d := New(t.TempDir())
	write := func(identity string) []byte {
		t.Helper()
		data, err := json.Marshal(pidInfo{PID: pid, Executable: os.Args[0], DataDir: d.dataDir, StartIdentity: identity})
		if err != nil {
			t.Fatal(err)
		}
		if err := safefile.WritePrivate(d.pidFile, data); err != nil {
			t.Fatal(err)
		}
		return data
	}

	if !processExists(pid) || processSignalable(pid) {
		t.Fatalf("access denied: processExists = %v, processSignalable = %v; want true, false",
			processExists(pid), processSignalable(pid))
	}
	want := write(identity)
	if running, got := d.IsRunning(); running {
		t.Fatalf("IsRunning() = true, %d for a gateway this caller cannot open", got)
	}
	if got, err := os.ReadFile(d.pidFile); err != nil || string(got) != string(want) {
		t.Fatalf("access denied removed or changed gateway.pid: %q, %v", got, err)
	}

	write("1")
	if running, _ := d.IsRunning(); running {
		t.Fatal("IsRunning() = true for a reused PID")
	}
	if _, err := os.Stat(d.pidFile); !os.IsNotExist(err) {
		t.Fatalf("access denied with a contradicting kernel creation time kept gateway.pid: %v", err)
	}

	openErr = windows.ERROR_INVALID_PARAMETER
	write(identity)
	if processExists(pid) {
		t.Fatal("ERROR_INVALID_PARAMETER: processExists = true; want gone")
	}
	if running, _ := d.IsRunning(); running {
		t.Fatal("IsRunning() = true for a PID the kernel no longer knows")
	}
	if _, err := os.Stat(d.pidFile); !os.IsNotExist(err) {
		t.Fatalf("gateway.pid of a gone process was kept: %v", err)
	}
}
