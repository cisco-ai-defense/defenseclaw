// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestGAP0509TransportDenialKeepsLocalToolReceipt(t *testing.T) {
	home := t.TempDir()
	logDir := filepath.Join(home, "logs")
	if err := os.Mkdir(logDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(logDir, "hook-failures.jsonl"), 0o700); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	opts := withDefaults(Options{Home: home, Event: "PreToolUse", FailMode: "closed", Stdout: &stdout, Stderr: io.Discard})
	opts.failurePayload = []byte(`{"session_id":"s","tool_use_id":"g509-transport-denied"}`)
	code := failUnreachable(opts, specs["claudecode"], "closed", "gateway unreachable")
	if !claudeBlocked(runResult{code: code, stdout: stdout.String()}) {
		t.Fatalf("transport failure did not deliver its closed answer: code=%d", code)
	}
	marker, err := os.ReadFile(filepath.Join(logDir, "hook-failures.dropped"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(marker, []byte(`"tool_id":"g509-transport-denied"`)) ||
		!bytes.Contains(marker, []byte(`"outcome":"fail_closed"`)) {
		t.Fatalf("transport denial has no per-ID local receipt: %q", marker)
	}
}

func TestGAP0509OpenTransportFailureStaysAllowed(t *testing.T) {
	home := t.TempDir()
	logDir := filepath.Join(home, "logs")
	if err := os.Mkdir(logDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(logDir, "hook-failures.jsonl"), 0o700); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	opts := withDefaults(Options{Home: home, Event: "PreToolUse", FailMode: "open", Stdout: &stdout, Stderr: io.Discard})
	opts.failurePayload = []byte(`{"session_id":"s","tool_use_id":"g509-transport-open"}`)
	code := failUnreachable(opts, specs["claudecode"], "open", "gateway unreachable")
	if claudeBlocked(runResult{code: code, stdout: stdout.String()}) {
		t.Fatalf("open transport failure was blocked: code=%d", code)
	}
	if _, err := os.Stat(filepath.Join(logDir, "hook-failures.dropped")); !os.IsNotExist(err) {
		t.Fatalf("open transport failure wrote a block receipt: %v", err)
	}
}
