//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package peercred

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// pidReuseProbeEnv carries "<listener address>,<test process PID>" to the
// creator process of TestLoopbackTCPConnOwnerPIDStaysReservedWhileTheSocketLives.
const pidReuseProbeEnv = "DC_PEERCRED_PID_REUSE_PROBE"

// TestLoopbackTCPPeerAccountPIDReuseCreator is the creator process of the
// test below: it connects to the listener, hands a duplicate of its socket
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

// processState opens pid and returns its creation time and whether it has
// exited; ok is false when no process object has that PID.
func processState(pid uint32) (created uint64, exited, ok bool) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, false, false
	}
	defer windows.CloseHandle(h) //nolint:errcheck // test query handle
	var creation, exit, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &creation, &exit, &kernel, &user) != nil {
		return 0, false, true
	}
	var code uint32
	_ = windows.GetExitCodeProcess(h, &code)
	return uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime), code != 259, true // 259 = STILL_ACTIVE
}

// TestLoopbackTCPConnOwnerPIDStaysReservedWhileTheSocketLives is the
// GAP-1131 PID-reuse case on the real kernel, built only on
// LoopbackTCPClientOwner and LoopbackTCPPeerAccount (it compiles on
// da4177e225 too). A creator process makes the client socket, hands it to a
// survivor (this test process, by DuplicateHandle) and exits. The table
// keeps naming the creator's PID; this checks the premise of the reuse case,
// that another process can get that PID while the connection lives. Windows
// keeps the exited creator's process object (and so its PID) while its
// socket lives, so no other process can hold the PID the table names: the
// lookup reaches the exited creator itself, on da4177e225 and on the head.
// Once the socket is closed the PID is released. A native run that fails
// here means the reuse case is reachable and the guard is the only defence.
func TestLoopbackTCPConnOwnerPIDStaysReservedWhileTheSocketLives(t *testing.T) {
	if os.Getenv(pidReuseProbeEnv) != "" {
		return
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
	// Output waits for the creator and closes this test's handle to it.
	out, err := creator.Output()
	if err != nil {
		t.Fatalf("creator: %v: %s", err, out)
	}
	creatorPID := uint32(creator.ProcessState.Pid())
	var dup windows.Handle
	for _, line := range strings.Split(string(out), "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "DUP "); ok {
			if n, err := strconv.ParseUint(value, 10, 64); err == nil {
				dup = windows.Handle(n)
			}
		}
	}
	if dup == 0 {
		t.Fatalf("the creator handed over no socket: %s", out)
	}
	server, ok := <-accepted
	if !ok {
		_ = windows.Closesocket(dup)
		t.Fatal("the listener accepted nothing")
	}
	local, remote := server.LocalAddr().(*net.TCPAddr), server.RemoteAddr().(*net.TCPAddr)
	owner, err := LoopbackTCPClientOwner(local, remote)
	if err != nil || owner.PID != creatorPID {
		_ = windows.Closesocket(dup)
		server.Close()
		t.Fatalf("the table names %+v, %v for the client end; want the exited creator %d", owner, err, creatorPID)
	}
	created, exited, held := processState(creatorPID)
	sid, accountErr := LoopbackTCPPeerAccount(local, remote)
	t.Logf("creator PID %d: held=%v exited=%v created=%d connection created=%d; LoopbackTCPPeerAccount=%q, %v",
		creatorPID, held, exited, created, owner.CreateTime, sid, accountErr)
	switch {
	case !held:
		t.Errorf("PID %d is free while the connection it owns lives: another process can get it (the reuse case is reachable)", creatorPID)
	case !exited:
		t.Errorf("PID %d names a running process, not the exited creator", creatorPID)
	case created > owner.CreateTime:
		t.Errorf("PID %d names a process that started after the connection: it was reused", creatorPID)
	}
	if err := windows.Closesocket(dup); err != nil {
		t.Fatalf("close the duplicated socket: %v", err)
	}
	server.Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		now, _, stillHeld := processState(creatorPID)
		if !stillHeld || now != created {
			return // released once its socket is gone
		}
		if time.Now().After(deadline) {
			t.Fatalf("PID %d is still the exited creator 10 s after its socket was closed: something else holds it", creatorPID)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
