// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"bufio"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Acceptance test of the RKRELAY review (GAP-0116): the signals Go would
// otherwise exit on (SIGABRT, SIGILL, SIGTRAP, SIGSYS, SIGSTKFLT, and
// SIGSEGV, SIGBUS, SIGFPE sent by kill) and the other terminating ones are
// held.
func TestRelayHoldsTheRemainingTerminatingSignals(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGABRT, syscall.SIGILL, syscall.SIGTRAP, syscall.SIGSYS, syscall.SIGSTKFLT,
		syscall.SIGXCPU, syscall.SIGXFSZ, syscall.SIGVTALRM, syscall.SIGPROF, syscall.SIGIO, syscall.SIGPWR,
		syscall.SIGSEGV, syscall.SIGBUS, syscall.SIGFPE} {
		cmd := exec.Command(os.Args[0], "hold-probe")
		out, _ := cmd.StdoutPipe()
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		line, _ := bufio.NewReader(out).ReadString('\n')
		if !strings.HasPrefix(line, "holding") {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("probe said %q", line)
		}
		exited := make(chan error, 1)
		go func() { exited <- cmd.Wait() }()
		_ = cmd.Process.Signal(sig)
		select {
		case err := <-exited:
			t.Errorf("%v: the relay exited (%v)", sig, err)
		case <-time.After(300 * time.Millisecond):
			_ = cmd.Process.Kill()
			<-exited
		}
	}
}
