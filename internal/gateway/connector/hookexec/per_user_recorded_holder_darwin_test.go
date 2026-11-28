// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package hookexec

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

// The macOS holder mark (GAP-1534) counts only the listener bound to the
// dialled address. A gateway that holds the wildcard listener while a decoy
// of the account holds the specific address does not get the mark: the decoy
// takes the connection, and an abandoned owner scan of it must stay refused.
func TestDarwinRecordedHolderMarkNeedsTheDialledAddress(t *testing.T) {
	// Each check gets its own deadline. One deadline for the whole test ran
	// out on a loaded macOS runner while the decoy (python3) was starting, and
	// the last check then read the expired context as "not held".
	holds := func(pid int, addr *net.TCPAddr) bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return darwinPIDHoldsListener(ctx, pid, addr)
	}

	specific, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer specific.Close()
	if !holds(os.Getpid(), specific.Addr().(*net.TCPAddr)) {
		t.Fatal("the process bound to the dialled address was not marked")
	}

	wildcard, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer wildcard.Close()
	port := wildcard.Addr().(*net.TCPAddr).Port
	dialled := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	if holds(os.Getpid(), dialled) {
		t.Fatal("a wildcard listener alone was marked as the listener of the dialled address")
	}

	// A decoy of this account on the specific address beside the wildcard.
	decoy := exec.Command("/usr/bin/python3", "-c", fmt.Sprintf(
		"import socket,sys,time\ns=socket.socket()\ns.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\ns.bind(('127.0.0.1',%d))\ns.listen(8)\nprint('up',flush=True)\ntime.sleep(60)", port))
	out, err := decoy.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := decoy.Start(); err != nil {
		t.Skipf("no decoy process: %v", err)
	}
	defer func() { _ = decoy.Process.Kill(); _ = decoy.Wait() }()
	buf := make([]byte, 3)
	if _, err := out.Read(buf); err != nil || string(buf[:2]) != "up" {
		t.Skipf("the decoy did not bind 127.0.0.1:%d beside the wildcard: %v %q", port, err, buf)
	}
	if holds(os.Getpid(), dialled) {
		t.Fatal("the wildcard holder was marked while a decoy holds the dialled address")
	}
	if !holds(decoy.Process.Pid, dialled) {
		t.Fatal("the decoy bound to the dialled address was not seen holding it (pid " + strconv.Itoa(decoy.Process.Pid) + ")")
	}
}
