// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookuser

import (
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"
)

// refusedLoopbackAddr is a loopback address that refuses every connection
// until the test ends: a TCP socket bound to it that never listens. Holding
// the port keeps any other process from serving on it, unlike the port of a
// closed httptest server (GAP-0031).
func refusedLoopbackAddr(t *testing.T) string {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	in4, ok := sa.(*syscall.SockaddrInet4)
	if !ok {
		t.Fatalf("socket name %T", sa)
	}
	return fmt.Sprintf("127.0.0.1:%d", in4.Port)
}

func TestRefusedLoopbackAddrRefuses(t *testing.T) {
	addr := refusedLoopbackAddr(t)
	if c, err := net.DialTimeout("tcp", addr, 2*time.Second); err == nil {
		c.Close()
		t.Fatalf("%s accepted a connection", addr)
	}
	// Nobody else can serve on it while the test holds it.
	if l, err := net.Listen("tcp", addr); err == nil {
		l.Close()
		t.Fatalf("another listener took %s", addr)
	}
}
