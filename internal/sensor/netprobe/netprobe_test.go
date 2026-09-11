// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package netprobe

import (
	"net"
	"testing"
)

// TestSnapshotReadsTheConnectionTable is the smoke test that the platform
// reader works on the host running the suite. It does not assert on any
// specific connection, because a CI box may have none -- only that the read
// itself succeeds and reports its own coverage.
func TestSnapshotReadsTheConnectionTable(t *testing.T) {
	connections, unattributed, err := Snapshot()
	if err != nil {
		// A read failure here is an environment fact, not a defect: a
		// container without /proc/net/tcp, or a runner without lsof, cannot
		// exercise this path at all. The parsers carry the real risk and are
		// tested directly, per platform, without touching the host.
		t.Skipf("this host cannot be read: %v", err)
	}
	// A count cannot be negative, so asserting that proves nothing. Assert
	// the invariants that actually hold for any host, including one with no
	// connections at all.
	if unattributed > len(connections) {
		t.Fatalf("%d unattributed out of %d connections", unattributed, len(connections))
	}
	attributed := 0
	for _, connection := range connections {
		if connection.Attributed() {
			attributed++
			if connection.PID <= 0 {
				t.Fatalf("connection reports attribution with no pid: %+v", connection)
			}
		}
		if connection.State == StateListen && connection.LocalPort == 0 {
			t.Fatalf("listener with no local port: %+v", connection)
		}
		if connection.RemotePort != 0 && connection.RemoteIP == nil {
			t.Fatalf("connection has a peer port but no peer address: %+v", connection)
		}
	}
	if attributed+unattributed != len(connections) {
		t.Fatalf("%d attributed + %d unattributed != %d connections: the coverage "+
			"numbers the snapshot reports do not add up",
			attributed, unattributed, len(connections))
	}
	t.Logf("%d connections, %d attributed, %d unattributed", len(connections), attributed, unattributed)
}

// TestPublicExcludesEverythingThatIsNotEgress pins the classification that
// keeps the signal from drowning: RFC1918 and link-local traffic is not shadow
// AI leaving the building.
func TestPublicExcludesEverythingThatIsNotEgress(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		ip     string
		public bool
		loop   bool
	}{
		{"104.18.0.1", true, false},
		{"2606:4700::1", true, false},
		{"127.0.0.1", false, true},
		{"::1", false, true},
		{"10.1.2.3", false, false},
		{"192.168.1.5", false, false},
		{"172.16.0.9", false, false},
		{"169.254.1.1", false, false},
		{"224.0.0.1", false, false},
		{"0.0.0.0", false, false},
	} {
		connection := Connection{RemoteIP: net.ParseIP(test.ip)}
		if got := connection.Public(); got != test.public {
			t.Errorf("Public(%s) = %t, want %t", test.ip, got, test.public)
		}
		if got := connection.Loopback(); got != test.loop {
			t.Errorf("Loopback(%s) = %t, want %t", test.ip, got, test.loop)
		}
	}
	// A connection with no peer address at all -- a listener -- is neither.
	listener := Connection{State: StateListen, LocalPort: 11434}
	if listener.Public() || listener.Loopback() {
		t.Error("a listener with no peer was classified as public or loopback")
	}
}

// TestLocalModelPortsCatchARenamedBinary pins the reason the port table exists
// separately from the process-name catalog.
func TestLocalModelPortsCatchARenamedBinary(t *testing.T) {
	t.Parallel()
	name, ok := LocalModelRuntimeForPort(11434)
	if !ok || name != "ollama" {
		t.Fatalf("LocalModelRuntimeForPort(11434) = %q, %t", name, ok)
	}
	if _, ok := LocalModelRuntimeForPort(443); ok {
		t.Fatal("443 was claimed by a local model runtime")
	}
}
