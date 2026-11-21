// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fakeProc(t *testing.T) (string, func(pid, ppid, pgrp int, start uint64, utime int, io string)) {
	proc := t.TempDir()
	return proc, func(pid, ppid, pgrp int, start uint64, utime int, io string) {
		d := filepath.Join(proc, fmt.Sprint(pid))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		// pid (comm) state ppid pgrp session tty tpgid flags minflt cminflt majflt cmajflt utime stime cutime cstime prio nice threads itreal starttime
		stat := fmt.Sprintf("%d (my (odd) tool) S %d %d %d 0 -1 0 0 0 0 0 %d 0 0 0 20 0 1 0 %d 0 0", pid, ppid, pgrp, pgrp, utime, start)
		_ = os.WriteFile(filepath.Join(d, "stat"), []byte(stat), 0o644)
		if io != "" {
			_ = os.WriteFile(filepath.Join(d, "io"), []byte(io), 0o644)
		}
	}
}

// GAP-0289: the tree is the agent's descendants and its group, tools in
// sessions of their own included, and a tool whose parent exited.
func TestProcTreeFollowsTheAgentsDescendants(t *testing.T) {
	proc, put := fakeProc(t)
	put(100, 1, 100, 10, 100, "rchar: 1000\nwchar: 24\nsyscr: 3\n") // the agent
	put(101, 100, 100, 11, 100, "")                                 // a child in its group
	put(102, 100, 102, 12, 50, "rchar: 100\n")                      // setsid tool (Claude Code Bash)
	put(103, 102, 102, 13, 50, "")                                  // its child
	put(200, 1, 200, 14, 999, "rchar: 5\n")                         // unrelated
	tr := &procTree{proc: proc, root: 100, known: map[int]uint64{}}
	u, ok := tr.usage()
	if !ok || u.CPU != 3*time.Second || u.IO != 1124 {
		t.Fatalf("usage %+v %v, want 3s CPU and 1124 bytes of 100..103 only", u, ok)
	}
	// The setsid tool's parent exits: the tool is re-parented to init and
	// still counted, by its start time.
	_ = os.RemoveAll(filepath.Join(proc, "100"))
	_ = os.RemoveAll(filepath.Join(proc, "101"))
	put(102, 1, 102, 12, 80, "rchar: 100\n")
	if u, ok := tr.usage(); !ok || u.CPU != 1300*time.Millisecond {
		t.Fatalf("after the agent exited: %+v %v, want the orphaned tool and its child (1.3s)", u, ok)
	}
	// A reused PID is another process.
	put(102, 1, 102, 99, 500, "")
	put(103, 1, 103, 98, 500, "")
	if u, ok := tr.usage(); ok {
		t.Fatalf("reused PIDs counted: %+v", u)
	}
	// GAP-0303: neither is a new process that reuses the agent's own PID.
	put(100, 1, 100, 77, 900, "")
	if u, ok := tr.usage(); ok {
		t.Fatalf("a process reusing the agent's PID counted: %+v", u)
	}
}

func TestParseProcStat(t *testing.T) {
	b, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Skip(err)
	}
	st, ok := parseProcStat(b)
	if !ok || st.ppid != os.Getppid() || st.start == 0 {
		t.Fatalf("%+v %v", st, ok)
	}
	if _, ok := parseProcStat([]byte("1 (x) S 0 1")); ok {
		t.Fatal("a short stat line parsed")
	}
	tr := newProcTree(os.Getpid())
	if _, ok := tr.usage(); !ok {
		t.Fatal("the live /proc reader found the test process's tree empty")
	}
}
