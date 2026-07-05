// Copyright 2026 Cisco Systems, Inc. and its affiliates
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

//go:build windows

package daemon

import (
	"errors"
	"net"
	"os"
	"strconv"
	"testing"
)

func TestListenerOwnerPIDNativeDisposableIPv4(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	pid, err := ListenerOwnerPID("127.0.0.1", port)
	if err != nil {
		t.Fatalf("ListenerOwnerPID: %v", err)
	}
	if pid != os.Getpid() {
		t.Fatalf("owner PID = %d, want current PID %d", pid, os.Getpid())
	}
}

func TestListenerOwnerPIDNativeDisposableIPv6(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	pid, err := ListenerOwnerPID("::1", port)
	if err != nil {
		t.Fatalf("ListenerOwnerPID: %v", err)
	}
	if pid != os.Getpid() {
		t.Fatalf("owner PID = %d, want current PID %d", pid, os.Getpid())
	}
}

func TestListenerOwnerPIDReportsMissingDisposablePort(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = ListenerOwnerPID("127.0.0.1", port)
	if !errors.Is(err, ErrNoListener) {
		t.Fatalf("port %s error = %v, want ErrNoListener", strconv.Itoa(port), err)
	}
}

func TestListenerAddressMatchingPreservesBindFamilyAndWildcardSemantics(t *testing.T) {
	tests := []struct {
		host   string
		actual string
		want   bool
	}{
		{"127.0.0.1", "127.0.0.1", true},
		{"127.0.0.1", "0.0.0.0", true},
		{"127.0.0.1", "127.0.0.2", false},
		{"127.0.0.1", "::1", false},
		{"0.0.0.0", "127.0.0.2", true},
		{"0.0.0.0", "::1", false},
		{"::1", "::", true},
		{"::1", "127.0.0.1", false},
		{"::", "127.0.0.1", true},
		{"localhost", "127.0.0.1", true},
		{"localhost", "::1", true},
		{"localhost", "10.0.0.1", false},
	}
	for _, tc := range tests {
		if got := listenerAddressMatches(tc.host, net.ParseIP(tc.actual)); got != tc.want {
			t.Errorf("listenerAddressMatches(%q, %q) = %v, want %v", tc.host, tc.actual, got, tc.want)
		}
	}
}
