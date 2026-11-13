// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/proofclock/proofclocktest"
)

const lateLockPeerHelperEnv = "DC_TEST_LATE_LOCK_PEER_HELPER"

// TestLateLockPeerHelper is the gateway of TestRestartProofNamesThePeerReadAtConnect:
// it accepts one connection and holds it until it is killed.
func TestLateLockPeerHelper(t *testing.T) {
	addr := os.Getenv(lateLockPeerHelperEnv)
	if addr == "" {
		t.Skip("helper process only")
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		os.Exit(2)
	}
	defer listener.Close()
	_, _ = os.Stdout.WriteString("ready\n")
	accepted, err := listener.Accept()
	if err != nil {
		os.Exit(3)
	}
	defer accepted.Close()
	_, _ = os.Stdout.WriteString("accepted\n")
	time.Sleep(30 * time.Second)
	os.Exit(0)
}

// TestRestartProofNamesThePeerReadAtConnect pins review 1 of rel-1-0-6
// GAP-0381 (finding 1, the reviewer's real-socket probe): a start can take
// the lock inside the observer's 25 ms sampling gap just before the call's
// deadline, and the gateway behind the call can exit before the proof runs.
// The proof then needs the process the kernel named behind the connection
// while it was open, so the record reads it when the call connects. With
// the read deferred to the proof (c68e763cc9) the exited holder was no
// longer named and the restart went unproven.
func TestRestartProofNamesThePeerReadAtConnect(t *testing.T) {
	clock := proofclocktest.Install(t)
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := reservation.Addr().String()
	_ = reservation.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestLateLockPeerHelper$")
	cmd.Env = append(os.Environ(), lateLockPeerHelperEnv+"="+addr)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	output := bufio.NewReader(pipe)
	if line, err := output.ReadString('\n'); err != nil || strings.TrimSpace(line) != "ready" {
		t.Fatalf("helper not ready: %q %v", line, err)
	}
	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if line, err := output.ReadString('\n'); err != nil || strings.TrimSpace(line) != "accepted" {
		t.Fatalf("helper did not accept: %q %v", line, err)
	}
	record := NewPerUserPeerRecord()
	record.capture(nil, client.LocalAddr(), client.RemoteAddr())
	// The read runs in the background from capture; the call goes on.
	select {
	case <-record.done:
	case <-time.After(3 * time.Second):
		t.Fatal("the peer read did not finish while the connection was open")
	}
	if got, ok := record.wait(time.Second); !ok || got.pid != cmd.Process.Pid {
		t.Fatalf("recorded peer = %+v %v, want the helper %d", got, ok, cmd.Process.Pid)
	}
	dir := t.TempDir()
	holdStartLock(t, dir)
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if !PerUserGatewayRestartProvenDuringCall(dir, record, false) {
		t.Fatal("a held start lock and an exited connected gateway gave no restart proof")
	}
	requireRestartProofBudgets(t, clock)
}
