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

//go:build linux

package netprobe

import (
	"testing"
)

// TestParseProcNetLine pins the /proc/net/tcp column contract.
//
// The reader is a positional parse of a kernel-formatted table, so the risk
// is not that it crashes: it is that a shifted column is decoded as a
// plausible address and the plane reports a peer that was never contacted.
// Every case below therefore asserts the decoded values, not just success.
func TestParseProcNetLine(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name       string
		line       string
		wantOK     bool
		wantInode  string
		wantLocal  int
		wantRemote string
		wantPort   int
		wantState  State
	}{
		{
			// 0100007F is 127.0.0.1 little-endian per word; 1F90 is 8080.
			name:       "established loopback client",
			line:       "   1: 0100007F:B3A6 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 456789 1 0000000000000000 20 4 30 10 -1",
			wantOK:     true,
			wantInode:  "456789",
			wantLocal:  45990,
			wantRemote: "127.0.0.1",
			wantPort:   8080,
			wantState:  StateEstablished,
		},
		{
			// State 0A is LISTEN; a listener has no peer.
			name:       "listener on all interfaces",
			line:       "   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 123456 1 0000000000000000 100 0 0 10 0",
			wantOK:     true,
			wantInode:  "123456",
			wantLocal:  8080,
			wantRemote: "0.0.0.0",
			wantPort:   0,
			wantState:  StateListen,
		},
		{
			// Anything the kernel does not label 01 or 0A is neither, and
			// must not be silently promoted to established.
			name:       "time-wait is neither established nor listening",
			line:       "   2: 0100007F:B3A6 0100007F:1F90 06 00000000:00000000 00:00000000 00000000  1000        0 0 1 0000000000000000 20 4 30 10 -1",
			wantOK:     true,
			wantInode:  "0",
			wantLocal:  45990,
			wantRemote: "127.0.0.1",
			wantPort:   8080,
			wantState:  StateOther,
		},
		{name: "header line", line: "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"},
		{name: "truncated row", line: "   1: 0100007F:B3A6 0100007F:1F90 01"},
		{name: "empty", line: ""},
		{
			name: "unparseable local address",
			line: "   1: NOTHEX:B3A6 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 456789 1 0000000000000000 20 4 30 10 -1",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			row, ok := parseProcNetLine(testCase.line)
			if ok != testCase.wantOK {
				t.Fatalf("parseProcNetLine ok = %v, want %v", ok, testCase.wantOK)
			}
			if !testCase.wantOK {
				return
			}
			if row.inode != testCase.wantInode {
				t.Errorf("inode = %q, want %q", row.inode, testCase.wantInode)
			}
			if row.connection.LocalPort != testCase.wantLocal {
				t.Errorf("local port = %d, want %d", row.connection.LocalPort, testCase.wantLocal)
			}
			if got := row.connection.RemoteIP.String(); got != testCase.wantRemote {
				t.Errorf("remote ip = %s, want %s", got, testCase.wantRemote)
			}
			if row.connection.RemotePort != testCase.wantPort {
				t.Errorf("remote port = %d, want %d", row.connection.RemotePort, testCase.wantPort)
			}
			if row.connection.State != testCase.wantState {
				t.Errorf("state = %v, want %v", row.connection.State, testCase.wantState)
			}
		})
	}
}

// TestParseHexAddress pins the per-word little-endian decode.
//
// This is the step that most easily produces a wrong but well-formed answer:
// flipping the whole buffer instead of each 32-bit word yields a valid IPv6
// address that belongs to somebody else.
func TestParseHexAddress(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name    string
		value   string
		wantIP  string
		wantPor int
		wantOK  bool
	}{
		{name: "ipv4 loopback", value: "0100007F:1F90", wantIP: "127.0.0.1", wantPor: 8080, wantOK: true},
		{name: "ipv4 unspecified", value: "00000000:0000", wantIP: "0.0.0.0", wantOK: true},
		{name: "ipv4 routable", value: "0201A8C0:01BB", wantIP: "192.168.1.2", wantPor: 443, wantOK: true},
		{
			// Four words, each reversed independently: ::1.
			name:   "ipv6 loopback",
			value:  "00000000000000000000000001000000:1F90",
			wantIP: "::1", wantPor: 8080, wantOK: true,
		},
		{name: "no port separator", value: "0100007F"},
		{name: "port not hex", value: "0100007F:ZZZZ"},
		{name: "address not hex", value: "NOTHEXAD:1F90"},
		{name: "address not a whole number of words", value: "010000:1F90"},
		{name: "empty address", value: ":1F90"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			ip, port, ok := parseHexAddress(testCase.value)
			if ok != testCase.wantOK {
				t.Fatalf("parseHexAddress(%q) ok = %v, want %v", testCase.value, ok, testCase.wantOK)
			}
			if !testCase.wantOK {
				return
			}
			if got := ip.String(); got != testCase.wantIP {
				t.Errorf("ip = %s, want %s", got, testCase.wantIP)
			}
			if port != testCase.wantPor {
				t.Errorf("port = %d, want %d", port, testCase.wantPor)
			}
		})
	}
}

// TestSocketOwnersStopsAtTheWantedSet pins the bound that keeps the poll
// cheap: an empty want set must not walk /proc at all.
func TestSocketOwnersStopsAtTheWantedSet(t *testing.T) {
	t.Parallel()
	if owners := socketOwners(nil); len(owners) != 0 {
		t.Fatalf("socketOwners(nil) returned %d owners; the walk must not run", len(owners))
	}
	// Every returned inode must be one that was asked for. Anything else
	// means the bound is not actually applied and the map is the old
	// whole-host build.
	wanted := map[string]bool{"this-inode-does-not-exist": true}
	for inode := range socketOwners(wanted) {
		if !wanted[inode] {
			t.Fatalf("socketOwners returned unwanted inode %q", inode)
		}
	}
}

// TestSocketInode pins the /proc/<pid>/fd link form.
func TestSocketInode(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		link   string
		want   string
		wantOK bool
	}{
		{link: "socket:[123456]", want: "123456", wantOK: true},
		{link: "socket:[0]", want: "0", wantOK: true},
		{link: "pipe:[123456]"},
		{link: "/dev/null"},
		{link: "socket:[123456"},
		{link: ""},
	} {
		t.Run(testCase.link, func(t *testing.T) {
			t.Parallel()
			got, ok := socketInode(testCase.link)
			if ok != testCase.wantOK {
				t.Fatalf("socketInode(%q) ok = %v, want %v", testCase.link, ok, testCase.wantOK)
			}
			if ok && got != testCase.want {
				t.Errorf("socketInode(%q) = %q, want %q", testCase.link, got, testCase.want)
			}
		})
	}
}
