// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package connector

import (
	"errors"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// A bound, non-listening Darwin socket can blackhole a connect. Use the
// reserved low-port test range, then release the probe socket so hook tests
// exercise the gateway-refused transport path.
func refusingAPIAddr(t *testing.T) string {
	t.Helper()
	return freeLoopbackAddrForOutageTest(t)
}

func TestRefusingAPIAddrHoldsItsPortAndRefuses(t *testing.T) {
	addr := refusingAPIAddr(t)
	_, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	// Prove a bound reservation excludes another listener. Release it before
	// dialing: Darwin otherwise waits for a TCP timeout instead of refusing.
	fd, err := refusingLoopbackSocket(port)
	if err != nil {
		t.Fatal(err)
	}
	if listener, listenErr := net.Listen("tcp", addr); listenErr == nil {
		_ = listener.Close()
		_ = closeReservedSocket(fd)
		t.Fatalf("another listener took %s while the test held it", addr)
	}
	if err := closeReservedSocket(fd); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("a connection to %s was accepted", addr)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("connect to %s: %v, want a refusal", addr, err)
	}
}
