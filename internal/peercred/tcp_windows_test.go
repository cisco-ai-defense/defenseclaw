//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package peercred

import (
	"net"
	"testing"

	"golang.org/x/sys/windows"
)

func TestTCPListenersNamesTheOwningProcess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	rows, err := TCPListeners(port)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rows {
		if r.Port != port {
			t.Fatalf("row of another port: %+v", r)
		}
		if r.PID == windows.GetCurrentProcessId() && r.IP.Equal(net.IPv4(127, 0, 0, 1)) {
			found = true
		}
	}
	if !found {
		t.Fatalf("own listener not in the table: %+v", rows)
	}
}

func TestProcessSIDOfThisProcessIsTheCurrentAccount(t *testing.T) {
	self, err := CurrentProcessSID()
	if err != nil || self == "" {
		t.Fatalf("current SID: %q %v", self, err)
	}
	sid, err := ProcessSID(windows.GetCurrentProcessId())
	if err != nil || sid != self {
		t.Fatalf("own process SID %q, want %q: %v", sid, self, err)
	}
	// The System process is never this account (an error when it cannot be opened).
	if sid, err := ProcessSID(4); err == nil && sid == self {
		t.Fatalf("System process reported as this account: %q", sid)
	}
}
