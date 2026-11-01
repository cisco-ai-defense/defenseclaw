// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"
)

// refusingAPIAddr returns a loopback host:port that refuses every connection
// for the whole test. Tests that run a generated shell hook must not bake the
// production API port 18970 into it: the hook's foreign-listener check treats
// another account holding that port (a shared host, or a developer machine
// with a gateway) as "not our gateway" and changes its behaviour, so the same
// test failed only where 18970 was taken.
//
// The port is bound, never listened on, and kept bound until the test ends:
// a connect gets a refusal, and no other test can take the port. It used to
// be a port a listener had just freed, and under load another test's mock
// gateway took it before the hook connected, so a hook that had to see an
// outage got that gateway's answer (rel-1-0-6 GAP-0317).
func refusingAPIAddr(t *testing.T) string {
	t.Helper()
	socket, err := reservedLoopbackSocket()
	if err != nil {
		t.Skipf("no loopback socket: %v", err)
	}
	t.Cleanup(func() { _ = closeReservedSocket(socket) })
	if err := syscall.Bind(socket, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("bind a loopback port: %v", err)
	}
	bound, err := syscall.Getsockname(socket)
	if err != nil {
		t.Fatalf("read the bound loopback port: %v", err)
	}
	inet, ok := bound.(*syscall.SockaddrInet4)
	if !ok || inet.Port == 0 {
		t.Fatalf("bound loopback address = %#v", bound)
	}
	return fmt.Sprintf("127.0.0.1:%d", inet.Port)
}

// TestRefusingAPIAddrHoldsItsPortAndRefuses pins rel-1-0-6 GAP-0317: no other
// listener can take the address while the test runs, and a hook that
// connects to it is refused at once.
func TestRefusingAPIAddrHoldsItsPortAndRefuses(t *testing.T) {
	addr := refusingAPIAddr(t)
	if listener, err := net.Listen("tcp", addr); err == nil {
		_ = listener.Close()
		t.Fatalf("another listener took %s while the test held it", addr)
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("a connection to %s was accepted", addr)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) && !isWindowsConnectionRefused(err) {
		t.Fatalf("connect to %s: %v, want a refusal", addr, err)
	}
}
