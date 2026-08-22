// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardianstate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadStateHappyPath(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"waiting_for_targets", "waiting_for_targets", StateWaitingForTargets},
		{"waiting_for_targets_lf", "waiting_for_targets\n", StateWaitingForTargets},
		{"ready", "ready", StateReady},
		{"ready_crlf_windows_typed", "ready\r\n", StateReady},
		{"unknown_body", "half_way", StateUnknown},
		{"empty_body", "", StateUnknown},
		{"only_whitespace", "   \n\t  ", StateUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, FileName)
			if err := os.WriteFile(path, []byte(tc.body), 0o644); err != nil {
				t.Fatalf("write: %v", err)
			}
			if got := ReadState(path); got != tc.want {
				t.Fatalf("body=%q got=%q want=%q", tc.body, got, tc.want)
			}
		})
	}
}

func TestReadStateMissingFile(t *testing.T) {
	dir := t.TempDir()
	if got := ReadState(filepath.Join(dir, "nope")); got != StateUnknown {
		t.Fatalf("missing file => %q, want empty", got)
	}
}

func TestReadStateOversized(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	// 200 bytes of `ready` padding — a legitimate state file is < 20 bytes.
	body := strings.Repeat("ready\n", 40)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := ReadState(path); got != StateUnknown {
		t.Fatalf("oversized file => %q, want empty (safety limit)", got)
	}
}

func TestWriteStateAtomicVisibleBody(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	if err := WriteState(path, StateWaitingForTargets); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := ReadState(path); got != StateWaitingForTargets {
		t.Fatalf("round trip: got %q, want %q", got, StateWaitingForTargets)
	}
	// Overwrite with the ready state; sidecar-observed body must
	// change on the next read.
	if err := WriteState(path, StateReady); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	if got := ReadState(path); got != StateReady {
		t.Fatalf("after overwrite: got %q, want %q", got, StateReady)
	}
}

func TestWriteStateRejectsUnknownLiteral(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	if err := WriteState(path, "waiting_for_config"); err == nil {
		t.Fatalf("WriteState should refuse a value the sidecar cannot map")
	}
	if err := WriteState(path, "typo_state"); err == nil {
		t.Fatalf("WriteState should refuse an arbitrary string")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatalf("no state file should have been left behind after a rejected write")
	}
}

func TestPathForStateRoot(t *testing.T) {
	// Ensures callers don't have to know FileName; the layout is a
	// single-source-of-truth join.
	got := PathForStateRoot("/tmp/dc/hook-guardian")
	want := filepath.Join("/tmp/dc/hook-guardian", FileName)
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
