// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProcGroupUsage(t *testing.T) {
	proc := t.TempDir()
	put := func(pid, stat, io string) {
		d := filepath.Join(proc, pid)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(filepath.Join(d, "stat"), []byte(stat), 0o644)
		if io != "" {
			_ = os.WriteFile(filepath.Join(d, "io"), []byte(io), 0o644)
		}
	}
	// pid (comm) state ppid pgrp session tty tpgid flags minflt cminflt majflt cmajflt utime stime ...
	put("100", "100 (claude) S 1 100 100 0 -1 0 0 0 0 0 150 50 0 0 20 0 1 0", "rchar: 1000\nwchar: 24\nsyscr: 3\n")
	put("101", "101 (my (odd) tool) R 100 100 100 0 -1 0 0 0 0 0 100 0 0 0 20 0 1 0", "")
	put("200", "200 (other) S 1 200 200 0 -1 0 0 0 0 0 999 999 0 0 20 0 1 0", "rchar: 5\nwchar: 5\n")
	put("self", "x", "")
	u, ok := procGroupUsage(proc, 100)
	if !ok || u.CPU != 3*time.Second || u.IO != 1024 {
		t.Fatalf("usage %+v %v, want 3s CPU and 1024 bytes of group 100 only", u, ok)
	}
	if _, ok := procGroupUsage(proc, 300); ok {
		t.Fatal("an empty group reported usage")
	}
	// The real /proc has the test process's own group.
	if _, ok := processGroupUsage(os.Getpid()); !ok && os.Getpid() == mustPgrp(t) {
		t.Fatal("the live /proc reader found no process of its own group")
	}
}

func mustPgrp(t *testing.T) int {
	t.Helper()
	b, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Skip(err)
	}
	g, _, ok := parseProcStat(b)
	if !ok {
		t.Fatal("cannot parse /proc/self/stat")
	}
	return g
}
