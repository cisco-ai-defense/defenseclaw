// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// leakMarkEnv is set in the test binary's environment before any test runs.
// Every process a test starts (the agent, exec, a task) inherits it, so a
// process still carrying this run's value after the tests is one the tests
// left behind (substrate-1 GAP-0246: detached sessions and their children
// survived every run).
const leakMarkEnv = "DC_RELAY_TEST_LEAKMARK"

// leakGrace is how long processes that are already being stopped get to
// go away before they count as left behind.
const leakGrace = 5 * time.Second

// markLeaks sets this run's mark and makes the test binary a child
// subreaper: a process a test started whose parent exits (a daemon, a
// detached session) is re-parented to the test binary, not to init, so it
// stays a descendant even when it cleared its environment (env -i) and lost
// the mark (substrate-1 GAP-0362).
func markLeaks() {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	_ = os.Setenv(leakMarkEnv, strconv.Itoa(os.Getpid())+"-"+hex.EncodeToString(b))
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		fmt.Printf("leak check: cannot become a child subreaper (%v); only marked processes are found\n", err)
	}
}

// leftBehind lists the live processes, other than this one, that are its
// descendants (by parent, the test binary being their subreaper) or whose
// environment carries this run's mark. Zombies count as gone.
func leftBehind() []int {
	mark := []byte(leakMarkEnv + "=" + os.Getenv(leakMarkEnv) + "\x00")
	self := os.Getpid()
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	parent := map[int]int{}
	var live []int
	marked := map[int]bool{}
	for _, d := range dirs {
		pid, err := strconv.Atoi(filepath.Base(d))
		if err != nil || pid == self {
			continue
		}
		st, err := os.ReadFile(d + "/stat")
		if err != nil {
			continue
		}
		i := bytes.LastIndexByte(st, ')')
		if i < 0 || i+2 >= len(st) {
			continue
		}
		f := bytes.Fields(st[i+1:])
		if len(f) < 2 || f[0][0] == 'Z' {
			continue
		}
		ppid, err := strconv.Atoi(string(f[1]))
		if err != nil {
			continue
		}
		parent[pid] = ppid
		live = append(live, pid)
		if env, err := os.ReadFile(d + "/environ"); err == nil && bytes.Contains(append(env, 0), mark) {
			marked[pid] = true
		}
	}
	var out []int
	for _, pid := range live {
		if marked[pid] || descends(pid, self, parent) {
			out = append(out, pid)
		}
	}
	return out
}

// descends reports whether pid's parent chain reaches root.
func descends(pid, root int, parent map[int]int) bool {
	for n := 0; n < 64; n++ {
		pp, ok := parent[pid]
		if !ok || pp <= 1 {
			return pp == root
		}
		if pp == root {
			return true
		}
		pid = pp
	}
	return false
}

// checkLeaks fails the run when a test left a process behind, and stops
// those processes by exact PID (they carry this run's mark, so they are
// this run's own).
func checkLeaks(code int) int {
	deadline := time.Now().Add(leakGrace)
	pids := leftBehind()
	for len(pids) > 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		pids = leftBehind()
	}
	if len(pids) == 0 {
		return code
	}
	for _, pid := range pids {
		cmd, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
		fmt.Printf("LEAK: process %d left behind by the tests: %q\n", pid, bytes.ReplaceAll(bytes.TrimRight(cmd, "\x00"), []byte{0}, []byte{' '}))
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	fmt.Printf("FAIL: %d process(es) left behind (GAP-0246)\n", len(pids))
	return 1
}
