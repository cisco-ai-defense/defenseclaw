// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"bufio"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// GAP-0116: the relay drops every catchable signal a process of the agent's
// user can send, so the agent cannot stop it and take its port. (SIGKILL
// and SIGSTOP never reach it because it is PID 1 of the actor's PID
// namespace; that part is the kernel's and is checked live in an actor.)
func TestRelayHoldsCatchableSignals(t *testing.T) {
	cmd := exec.Command(os.Args[0], "hold-probe")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	line, _ := bufio.NewReader(out).ReadString('\n')
	if !strings.HasPrefix(line, "holding") {
		t.Fatalf("probe said %q", line)
	}
	// One Wait, after the read (os/exec: no Wait before the pipe reads end).
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-exited })
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT,
		syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGPIPE, syscall.SIGALRM, syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU} {
		if err := cmd.Process.Signal(sig); err != nil {
			t.Fatalf("%v: %v", sig, err)
		}
		select {
		case err := <-exited:
			t.Fatalf("the relay stopped on %v: %v", sig, err)
		case <-time.After(150 * time.Millisecond):
		}
	}
	// Still answering: not stopped either (SIGTSTP is caught, not obeyed).
	if st, err := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/stat"); err != nil || strings.Contains(string(st), ") T ") {
		t.Fatalf("the relay is stopped: %q %v", st, err)
	}
}
