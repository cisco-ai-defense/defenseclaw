// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

// refusingLoopbackAddr is a 127.0.0.1 port held for the whole test on which
// every connect is refused. The port is the local end of a loopback
// connection the test keeps open: no socket listens on it, so a connect is
// refused at once, and while it is in use the kernel gives it to no other
// port-0 bind or outgoing connection. A port that was only freed
// (reservedLoopbackAddr) could be taken by another test process of the same
// account on a busy build box, and the per-user owner proof accepted that
// listener (rel-1-0-6 GAP-0406).
//
// A socket that is bound and never listens does not do on macOS: Linux
// refuses a connect to it, but the BSD stack drops the SYN, so the connect
// hangs until the hook's budget ends and the call reads as a gateway that
// took it and did not answer, not as one that is down.
func refusingLoopbackAddr(t *testing.T) string {
	t.Helper()
	peer, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hold, err := net.Dial("tcp", peer.Addr().String())
	if err != nil {
		_ = peer.Close()
		t.Fatal(err)
	}
	accepted, err := peer.Accept()
	_ = peer.Close()
	if err != nil {
		_ = hold.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = hold.Close()
		_ = accepted.Close()
	})
	addr := hold.LocalAddr().String()
	probe, err := net.DialTimeout("tcp", addr, time.Second)
	if err == nil {
		_ = probe.Close()
		t.Fatalf("held port %s accepted a connection", addr)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("held port %s: connect = %v, want it refused", addr, err)
	}
	return addr
}
