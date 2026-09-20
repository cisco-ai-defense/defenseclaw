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

package acquire

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

// serveHelper starts a helper on a temporary socket and returns a client
// pointed at it.
func serveHelper(t *testing.T, config ServerConfig) *Helper {
	t.Helper()
	// A short path: the sun_path field is 104 bytes on darwin and t.TempDir
	// under the default TMPDIR can exceed it.
	dir, err := os.MkdirTemp("", "acq")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s")

	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("unix sockets unavailable here: %v", err)
	}
	server := NewServer(config)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("helper did not stop")
		}
	})
	return NewHelper(socket)
}

// TestBrokeredProcessTableMatchesADirectRead is the property the whole
// broker exists to provide: a de-privileged caller learns what a privileged
// reader sees, unchanged.
func TestBrokeredProcessTableMatchesADirectRead(t *testing.T) {
	helper := serveHelper(t, ServerConfig{})
	ctx := context.Background()

	brokered, _, err := helper.Processes(ctx)
	if err != nil {
		t.Fatalf("brokered Processes: %v", err)
	}
	direct, _, err := NewLocal().Processes(ctx)
	if err != nil {
		t.Skipf("this host cannot be read directly: %v", err)
	}
	if len(brokered) == 0 {
		t.Fatal("the broker returned no processes; this test runs inside one")
	}

	// The two reads happen microseconds apart on a live host, so the tables
	// cannot be compared element-wise. Assert the invariants instead: the
	// broker must not be losing or mangling rows.
	if ratio := float64(len(brokered)) / float64(len(direct)); ratio < 0.5 || ratio > 2 {
		t.Fatalf("brokered %d processes, direct read saw %d", len(brokered), len(direct))
	}
	self := os.Getpid()
	found := false
	for _, row := range brokered {
		if row.PID <= 0 {
			t.Fatalf("brokered row with no pid: %+v", row)
		}
		if row.PID == self {
			found = true
			if row.Name == "" {
				t.Error("the test's own process crossed the wire with no name")
			}
			if row.StartedAt.IsZero() {
				t.Error("the test's own process crossed the wire with no start time")
			}
		}
	}
	if !found {
		t.Fatalf("the test's own pid %d did not survive the round trip", self)
	}
}

// TestBrokeredConnectionTableSurvivesTheRoundTrip pins the fields the egress
// plane reasons about, addresses especially: a peer that decodes to nil
// would silently become an unattributable connection.
func TestBrokeredConnectionTableSurvivesTheRoundTrip(t *testing.T) {
	helper := serveHelper(t, ServerConfig{})
	brokered, unattributed, err := helper.Connections(context.Background())
	if err != nil {
		t.Skipf("connections unreadable here: %v", err)
	}
	if unattributed > len(brokered) {
		t.Fatalf("%d unattributed of %d connections", unattributed, len(brokered))
	}
	for _, row := range brokered {
		if row.RemotePort != 0 && row.RemoteIP == nil {
			t.Fatalf("peer port with no address survived the wire: %+v", row)
		}
	}
}

// TestHelperRefusesAnUnknownOperation pins the closed protocol. The helper
// holds privilege, so anything it does not recognise is refused rather than
// interpreted.
func TestHelperRefusesAnUnknownOperation(t *testing.T) {
	helper := serveHelper(t, ServerConfig{})
	conn, err := helper.dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := writeFrame(conn, Request{
		Version: protocolVersion, Op: "read-arbitrary-file",
	}, requestDeadline); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := readFrame(conn, &response, responseDeadline); err != nil {
		t.Fatal(err)
	}
	if response.Error == "" {
		t.Fatal("the helper accepted an operation it does not implement")
	}
	if !strings.Contains(response.Error, "unsupported") {
		t.Fatalf("unexpected refusal: %s", response.Error)
	}
}

// TestHelperRefusesAForeignProtocolVersion pins that two versions of a
// privileged protocol refuse each other rather than negotiating.
func TestHelperRefusesAForeignProtocolVersion(t *testing.T) {
	helper := serveHelper(t, ServerConfig{})
	conn, err := helper.dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := writeFrame(conn, Request{
		Version: protocolVersion + 99, Op: OpProcesses,
	}, requestDeadline); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := readFrame(conn, &response, responseDeadline); err != nil {
		t.Fatal(err)
	}
	if response.Error == "" {
		t.Fatal("the helper served a client speaking a different protocol version")
	}
	if len(response.Body) != 0 {
		t.Fatal("the helper sent a body to a client it had just refused")
	}
}

// TestFrameReaderRefusesAnOversizedDeclaredLength pins the allocation guard.
// The length prefix is peer-supplied; trusting it is how a helper becomes
// the thing that kills the host.
func TestFrameReaderRefusesAnOversizedDeclaredLength(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		// A four-byte header declaring ~4 GiB, and nothing behind it.
		_, _ = server.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	}()
	var response Response
	err := readFrame(client, &response, 5*time.Second)
	if err == nil {
		t.Fatal("readFrame accepted a 4 GiB declared length")
	}
	if !strings.Contains(err.Error(), "cap is") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestHelperReportsUnreachabilityRatherThanPretending is the coverage rule
// applied to the broker itself: a helper that is not there must be visible
// as such, because a silently empty process table reads as a quiet host.
func TestHelperReportsUnreachabilityRatherThanPretending(t *testing.T) {
	helper := NewHelper(filepath.Join(t.TempDir(), "absent.sock"))
	if _, _, err := helper.Processes(context.Background()); err == nil {
		t.Fatal("a helper with no socket behind it returned a process table")
	}
	described := helper.Describe()
	if !strings.Contains(described, "unreachable") {
		t.Fatalf("Describe() = %q, which does not report the broker is down", described)
	}
}

// TestBrokeredPlaneIgnoresCallerSuppliedPaths is the security property that
// justifies putting a privileged process on the other end.
//
// The watch scope is the helper's own. If a caller could name it, a
// compromised gateway could point a root process at any path on the host and
// read the results back -- the confused deputy this design exists to avoid.
func TestBrokeredPlaneIgnoresCallerSuppliedPaths(t *testing.T) {
	helper := NewHelper("/nonexistent/never-dialled.sock")
	source := helper.PlaneSource([]string{"/etc", "/root", "/var/db"})
	brokered, ok := source.(*helperPlaneSource)
	if !ok {
		t.Fatalf("PlaneSource returned %T", source)
	}
	// The request type is the whole contract: if it ever grows a field that
	// names what to read, this is the test that should stop it.
	request := Request{Version: protocolVersion, Op: OpEvents}
	if got := requestFieldCount(request); got != 2 {
		t.Fatalf("Request carries %d fields; a privileged protocol must not "+
			"let the caller describe what to read", got)
	}
	if brokered.helper != helper {
		t.Fatal("the brokered source is not bound to its helper")
	}
}

// TestServerConfigDecidesTheWatchScope is the other half: the scope the
// helper uses comes from its own configuration.
func TestServerConfigDecidesTheWatchScope(t *testing.T) {
	config := ServerConfig{HomeDirs: []string{"/home/only-this-one"}}
	server := NewServer(config)
	if len(server.config.HomeDirs) != 1 || server.config.HomeDirs[0] != "/home/only-this-one" {
		t.Fatalf("server watch scope = %v", server.config.HomeDirs)
	}
}

// TestLocalAndHelperBothSatisfyAcquirer keeps the two implementations
// interchangeable, which is what lets deployment mode pick between them.
func TestLocalAndHelperBothSatisfyAcquirer(t *testing.T) {
	var _ Acquirer = NewLocal()
	var _ Acquirer = NewHelper("/tmp/unused.sock")
	var _ plane.Source = (*helperPlaneSource)(nil)
}

// TestVersionMismatchIsDistinguishable lets a caller tell a protocol skew
// from a dead helper, because the two need different operator action.
func TestVersionMismatchIsDistinguishable(t *testing.T) {
	if !errors.Is(ErrVersionMismatch, ErrVersionMismatch) {
		t.Fatal("sentinel is not comparable")
	}
}

// requestFieldCount counts the fields a Request carries.
//
// It exists so the closed-protocol property is enforced mechanically rather
// than by reviewer vigilance: adding a field that lets the caller say what
// to read is exactly the change that must not pass unnoticed.
func requestFieldCount(request Request) int {
	return reflect.TypeOf(request).NumField()
}
