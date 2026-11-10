// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// listenManagedRecordSocket serves a syslog-like datagram socket for one test
// and points the managed record at it.
func listenManagedRecordSocket(t *testing.T) *net.UnixConn {
	t.Helper()
	dir, err := os.MkdirTemp("", "dcrec")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "log")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Skipf("no unix datagram socket here: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	managedRecorderTestMu.Lock()
	previous := managedHookSyslogSockets
	managedHookSyslogSockets = []string{filepath.Join(dir, "missing"), path}
	t.Cleanup(func() {
		managedHookSyslogSockets = previous
		managedRecorderTestMu.Unlock()
	})
	return conn
}

// GAP-1029: a managed hook that denies a call after its retry budget leaves a
// record of it on the host (a managed standard account may have no
// hook-failures.jsonl): the local syslog gets one line that names the
// decision, the reason and the call's session and tool id, and never the
// payload.
func TestManagedHookDenialLeavesALocalSyslogRecordNamingTheToolCall(t *testing.T) {
	conn := listenManagedRecordSocket(t)
	recordManagedHookDecision(
		Options{Event: "PreToolUse", failurePayload: []byte(`{"session_id":"sess-9","tool_use_id":"toolu_77","tool_input":{"command":"secret-payload"}}`)},
		spec{connector: "claudecode", hookName: "claude-code-hook"},
		"gateway busy", "transport", "closed", true,
	)
	buffer := make([]byte, 2048)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buffer)
	if err != nil {
		t.Fatalf("no record reached the syslog socket: %v", err)
	}
	line := string(buffer[:n])
	for _, want := range []string{`decision="block"`, `tool_id="toolu_77"`, `session_id="sess-9"`, `reason="gateway busy"`, "<28>"} {
		if !strings.Contains(line, want) {
			t.Errorf("record %q lacks %s", line, want)
		}
	}
	if strings.Contains(line, "secret-payload") || strings.Contains(line, "\n") {
		t.Errorf("record carries the payload or a line break: %q", line)
	}
}

// The benign twin: with no syslog socket the record is dropped quietly and in
// bounded time; a hook's decision never waits on it.
func TestManagedHookDecisionRecordWithoutASyslogSocketIsQuiet(t *testing.T) {
	managedRecorderTestMu.Lock()
	previous := managedHookSyslogSockets
	managedHookSyslogSockets = []string{filepath.Join(t.TempDir(), "absent")}
	defer func() {
		managedHookSyslogSockets = previous
		managedRecorderTestMu.Unlock()
	}()
	started := time.Now()
	writeManagedHookDecisionRecord("DefenseClawGateway", "DEGRADED", "line")
	if elapsed := time.Since(started); elapsed > managedHookRecordWriteWait+time.Second {
		t.Fatalf("the record took %s", elapsed)
	}
}
