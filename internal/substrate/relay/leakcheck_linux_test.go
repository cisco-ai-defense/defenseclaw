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

func markLeaks() {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	_ = os.Setenv(leakMarkEnv, strconv.Itoa(os.Getpid())+"-"+hex.EncodeToString(b))
}

// leftBehind lists the live processes, other than this one, whose
// environment carries this run's mark. Zombies count as gone.
func leftBehind() []int {
	mark := []byte(leakMarkEnv + "=" + os.Getenv(leakMarkEnv) + "\x00")
	self := os.Getpid()
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	var out []int
	for _, d := range dirs {
		pid, err := strconv.Atoi(filepath.Base(d))
		if err != nil || pid == self {
			continue
		}
		env, err := os.ReadFile(d + "/environ")
		if err != nil || !bytes.Contains(append(env, 0), mark) {
			continue
		}
		if st, err := os.ReadFile(d + "/stat"); err == nil {
			if i := bytes.LastIndexByte(st, ')'); i > 0 && i+2 < len(st) && st[i+2] == 'Z' {
				continue
			}
		}
		out = append(out, pid)
	}
	return out
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
