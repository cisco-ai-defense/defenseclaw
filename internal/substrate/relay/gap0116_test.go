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
	"testing"
	"time"
)

// GAP-0116: the relay drops every signal of heldSignals a process of the
// agent's user can send (every one whose default ends or stops a process
// and that can be caught), so the agent cannot stop it with one and take its
// port. SIGKILL and SIGSTOP cannot be caught: gVisor delivers them to an
// actor's PID 1, so only running the agent as another user keeps them away
// (TestSeparatedAgentCannotSignalTheRelay; the E4 live check covers gVisor).
func TestRelayHoldsTerminatingSignals(t *testing.T) {
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
	for _, sig := range heldSignals {
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
