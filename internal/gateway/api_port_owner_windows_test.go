// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"fmt"
	"net"
	"testing"
)

// The listener table names this process as the holder of its own port
// (not another account), and a port nobody listens on (what an excluded
// port range looks like in the table) has no holder (REVIEW-code-delta-d962
// P2-1/P2-2).
func TestAPIPortHolderOfReadsTheListenerTable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	info, err := apiPortHolderOf(ln.Addr().String())
	if err != nil || !info.Found || info.Other {
		t.Fatalf("own listener: %+v %v", info, err)
	}
	wild, err := apiPortHolderOf(fmt.Sprintf(":%d", ln.Addr().(*net.TCPAddr).Port))
	if err != nil || !wild.Found || wild.Other {
		t.Fatalf("wildcard bind over the own listener: %+v %v", wild, err)
	}

	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := free.Addr().String()
	_ = free.Close()
	if info, err := apiPortHolderOf(addr); err != nil || info.Found || info.Other {
		t.Fatalf("no listener, no holder: %+v %v", info, err)
	}
}
