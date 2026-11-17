//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package peercred

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// pidReuseProbeEnv carries "<listener address>,<test process PID>" to the
// creator process of TestLoopbackTCPPeerAccountRefusesAReusedPID.
const pidReuseProbeEnv = "DC_PEERCRED_PID_REUSE_PROBE"

// pidReuseRequiredEnv=1 turns the probe's skips into failures (the
// fail-before and pass-after evidence runs).
const pidReuseRequiredEnv = "DC_REQUIRE_PID_REUSE_PROBE"

// TestLoopbackTCPPeerAccountPIDReuseCreator is the creator process of the
// probe below: it connects to the listener, hands a duplicate of its socket
// to the test process and exits. In a normal run it does nothing.
func TestLoopbackTCPPeerAccountPIDReuseCreator(t *testing.T) {
	spec := os.Getenv(pidReuseProbeEnv)
	if spec == "" {
		return
	}
	fail := func(format string, args ...any) {
		fmt.Printf("ERR "+format+"\n", args...)
		os.Exit(2)
	}
	addr, parentText, ok := strings.Cut(spec, ",")
	parentPID, err := strconv.ParseUint(parentText, 10, 32)
	if !ok || err != nil {
		fail("bad probe spec %q", spec)
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fail("dial: %v", err)
	}
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		fail("raw conn: %v", err)
	}
	var socket windows.Handle
	if err := raw.Control(func(fd uintptr) { socket = windows.Handle(fd) }); err != nil {
		fail("socket handle: %v", err)
	}
	parent, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, uint32(parentPID))
	if err != nil {
		fail("open the test process: %v", err)
	}
	var dup windows.Handle
	if err := windows.DuplicateHandle(windows.CurrentProcess(), socket, parent, &dup, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		fail("duplicate the socket: %v", err)
	}
	fmt.Printf("DUP %d\n", uintptr(dup))
	os.Exit(0)
}

// TestLoopbackTCPPeerAccountRefusesAReusedPID is a black-box probe on the
// real connection table (GAP-1131), built only on LoopbackTCPPeerAccount and
// LoopbackTCPClientOwner. A creator process makes the client socket, hands
// it to a survivor (this test process, by DuplicateHandle) and exits; the
// table keeps naming the creator's PID. Once a later process gets that PID,
// the Secure Client caller account lookup must refuse to name its account.
// It skips when the table stops naming the creator or Windows does not reuse
// the PID within a minute, unless DC_REQUIRE_PID_REUSE_PROBE=1.
func TestLoopbackTCPPeerAccountRefusesAReusedPID(t *testing.T) {
	if os.Getenv(pidReuseProbeEnv) != "" {
		return
	}
	skip := t.Skipf
	if os.Getenv(pidReuseRequiredEnv) == "1" {
		skip = t.Fatalf
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- conn
	}()
	creator := exec.Command(os.Args[0], "-test.run=^TestLoopbackTCPPeerAccountPIDReuseCreator$")
	creator.Env = append(os.Environ(),
		pidReuseProbeEnv+"="+ln.Addr().String()+","+strconv.FormatUint(uint64(windows.GetCurrentProcessId()), 10))
	out, err := creator.Output()
	if err != nil {
		t.Fatalf("creator: %v: %s", err, out)
	}
	creatorPID := uint32(creator.ProcessState.Pid())
	var dup windows.Handle
	for _, line := range strings.Split(string(out), "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "DUP "); ok {
			n, err := strconv.ParseUint(value, 10, 64)
			if err == nil {
				dup = windows.Handle(n)
			}
		}
	}
	if dup == 0 {
		t.Fatalf("the creator handed over no socket: %s", out)
	}
	defer windows.CloseHandle(dup) //nolint:errcheck // test cleanup
	server, ok := <-accepted
	if !ok {
		t.Fatal("the listener accepted nothing")
	}
	defer server.Close()
	local, remote := server.LocalAddr().(*net.TCPAddr), server.RemoteAddr().(*net.TCPAddr)
	if owner, err := LoopbackTCPClientOwner(local, remote); err != nil || owner.PID != creatorPID {
		skip("the table does not name the exited creator %d: %+v %v", creatorPID, owner, err)
	}
	// Take the PID: start suspended, detached processes (they never run)
	// until one gets it. The first ones stay alive (a most-recently-freed
	// reuse order hands the PID out early); later ones are ended at once,
	// so an oldest-first order cycles through the free IDs within the
	// minute. Every taker is ended when the test returns.
	cmd := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	var kept []*exec.Cmd
	defer func() {
		for _, c := range kept {
			_ = c.Process.Kill()
			_ = c.Wait()
		}
	}()
	reused, takers := false, 0
	for deadline := time.Now().Add(time.Minute); !reused && time.Now().Before(deadline); takers++ {
		c := exec.Command(cmd, "/c", "exit")
		c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED | windows.DETACHED_PROCESS}
		if err := c.Start(); err != nil {
			t.Fatalf("start a PID taker: %v", err)
		}
		reused = uint32(c.Process.Pid) == creatorPID
		if reused || len(kept) < 200 {
			kept = append(kept, c)
			continue
		}
		_ = c.Process.Kill()
		_ = c.Wait()
	}
	if !reused {
		skip("PID %d was not reused within a minute (%d processes)", creatorPID, takers)
	}
	if owner, err := LoopbackTCPClientOwner(local, remote); err != nil || owner.PID != creatorPID {
		skip("the table no longer names PID %d: %+v %v", creatorPID, owner, err)
	}
	sid, err := LoopbackTCPPeerAccount(local, remote)
	if err == nil {
		t.Fatalf("LoopbackTCPPeerAccount named %s, the account of a process that got PID %d after the connection was made; want a refusal", sid, creatorPID)
	}
	if !strings.Contains(err.Error(), "started after") {
		t.Fatalf("LoopbackTCPPeerAccount failed with %v; want the reused-PID refusal", err)
	}
	t.Logf("PID %d reused after %d processes and refused: %v", creatorPID, takers, err)
}
