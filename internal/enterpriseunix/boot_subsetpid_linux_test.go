// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package enterpriseunix

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// GAP-2101: a /proc mounted with subset=pid has the process directories and
// /proc/self but no /proc/stat. Managed verify failed managed_launch_scan_unknown
// there ("lstat /proc/stat") although every agent process was readable. The
// boot instant now comes from the clocks on such a mount, and the start time
// of each process is the same one /proc/stat btime gives.
func TestLinuxProcessScansUseTheClockBootTimeUnderSubsetPID(t *testing.T) {
	root := t.TempDir()
	const boot = int64(1_760_000_000)
	saved := bootFromClock
	bootFromClock = func() (int64, bool) { return boot, true }
	t.Cleanup(func() { bootFromClock = saved })

	write := func(rel, body string) {
		t.Helper()
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("proc/self/stat", "1 (self) S 0\n")
	// A claude process started 12.5 s (1250 ticks) after boot.
	write("proc/4242/cmdline", "claude\x00--print\x00")
	write("proc/4242/stat", "4242 (claude) S 1 4242 4242 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 1250 0 0\n")
	if _, err := os.Lstat(filepath.Join(root, "proc", "stat")); !os.IsNotExist(err) {
		t.Fatalf("fixture must have no /proc/stat, got %v", err)
	}
	env := &Env{Root: root}
	want := time.Unix(boot, 0).Add(12500 * time.Millisecond)

	sessions, err := env.linuxAgentSessionsWithError()
	if err != nil {
		t.Fatalf("agent session scan under subset=pid: %v", err)
	}
	if len(sessions) != 1 || sessions[0].PID != 4242 || !sessions[0].Started.Equal(want) {
		t.Fatalf("sessions = %+v, want pid 4242 started %s", sessions, want)
	}
	processes := env.linuxProcesses()
	if len(processes) != 1 || !processes[0].Started.Equal(want) {
		t.Fatalf("processes = %+v, want one started %s", processes, want)
	}
	bundle, err := env.bundleLinuxProcesses(context.Background(), map[string]string{"claude": "claudecode"})
	if err != nil {
		t.Fatalf("bundle session scan under subset=pid: %v", err)
	}
	if len(bundle) != 1 || !bundle[0].StartedAt.Equal(want) {
		t.Fatalf("bundle processes = %+v, want one started %s", bundle, want)
	}
}

// Without /proc/self the directory is not a process table: the scan stays
// unknown instead of reading the host clock (the lowered-health case of
// TestManagedLaunchUnavailableLinuxProcLowersHealth).
func TestLinuxBootSecondsWithoutProcessTableStaysUnavailable(t *testing.T) {
	saved := bootFromClock
	bootFromClock = func() (int64, bool) { t.Fatal("clock read without a process table"); return 0, false }
	t.Cleanup(func() { bootFromClock = saved })
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "proc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Env{Root: root}).linuxBootSeconds(); err == nil {
		t.Fatal("linuxBootSeconds succeeded with no /proc/stat and no /proc/self")
	}
}
