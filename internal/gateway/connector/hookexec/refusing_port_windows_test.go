// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"fmt"
	"syscall"
	"testing"
)

// refusingLoopbackAddr is a 127.0.0.1 port held for the whole test by a TCP
// socket that is bound and never listens: every connect to it is refused,
// and no other process can bind it while the test runs. A port that was only
// freed (reservedLoopbackAddr) could be taken by another test process of the
// same account on a busy build box, and the per-user owner proof accepted
// that listener (rel-1-0-6 GAP-0406).
func refusingLoopbackAddr(t *testing.T) string {
	t.Helper()
	handle, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Closesocket(handle) })
	if err := syscall.Bind(handle, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	bound, err := syscall.Getsockname(handle)
	if err != nil {
		t.Fatal(err)
	}
	inet, ok := bound.(*syscall.SockaddrInet4)
	if !ok || inet.Port == 0 {
		t.Fatalf("bound address %#v", bound)
	}
	return fmt.Sprintf("127.0.0.1:%d", inet.Port)
}
