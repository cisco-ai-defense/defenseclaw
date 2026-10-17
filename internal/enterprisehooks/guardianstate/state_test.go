// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardianstate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
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

// TestPathForDataDirUsesProtectedAuthorizationDir pins the single
// writer/reader helper (issue #896): the state file lives in the protected
// hook guardian authorization directory the services are configured with,
// and never inside the gateway-writable data_dir.
func TestPathForDataDirUsesProtectedAuthorizationDir(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "runtime")
	authDir := filepath.Join(root, "hook-guardian-state")

	t.Setenv(managed.HookGuardianAuthorizationDirEnv, authDir)
	if got, want := PathForDataDir(dataDir), filepath.Join(authDir, FileName); got != want {
		t.Fatalf("configured authorization dir: got %q, want %q", got, want)
	}

	t.Setenv(managed.HookGuardianAuthorizationDirEnv, "")
	got := PathForDataDir(dataDir)
	if want := filepath.Join(dataDir+"-hook-guardian", FileName); got != want {
		t.Fatalf("default authorization dir: got %q, want %q", got, want)
	}
	if rel, err := filepath.Rel(dataDir, got); err == nil && !strings.HasPrefix(rel, "..") {
		t.Fatalf("state path %q is inside the gateway-writable data_dir %q", got, dataDir)
	}
}

func TestEncodeMatchesWriteStateBody(t *testing.T) {
	for _, state := range []string{StateWaitingForTargets, StateReady} {
		body, err := Encode(state)
		if err != nil {
			t.Fatalf("Encode(%q): %v", state, err)
		}
		path := filepath.Join(t.TempDir(), FileName)
		if err := WriteState(path, state); err != nil {
			t.Fatalf("WriteState(%q): %v", state, err)
		}
		written, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(written) != string(body) {
			t.Fatalf("WriteState body %q != Encode body %q", written, body)
		}
	}
	if _, err := Encode("waiting_for_config"); err == nil {
		t.Fatal("Encode accepted a literal the sidecar cannot map")
	}
}

func TestPathForPlatform(t *testing.T) {
	dataDir := filepath.Join("var", "lib", "defenseclaw")
	authDir := filepath.Join("var", "lib", "defenseclaw-hook-guardian")
	if got, want := PathForPlatform(false, dataDir, authDir), PathForDataDir(dataDir); got != want {
		t.Fatalf("non-standalone path = %q, want %q", got, want)
	}
	if got, want := PathForPlatform(true, dataDir, authDir), filepath.Join(authDir, FileName); got != want {
		t.Fatalf("standalone Unix path = %q, want %q", got, want)
	}
}

// TestReadCurrentStateExpiresStaleReady pins the freshness rule the gateway
// applies (issue #896 review): the readiness file survives guardian restarts
// and non-purge uninstall, so a `ready` the guardian stopped re-publishing
// (crash, kill, reinstall before the new guardian started) must fall back to
// the safe default instead of being honored forever.
func TestReadCurrentStateExpiresStaleReady(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	if err := WriteState(path, StateReady); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	written := info.ModTime()

	for _, tc := range []struct {
		name string
		now  time.Time
		want string
	}{
		{"just_published", written, StateReady},
		{"within_max_age", written.Add(ReadyMaxAge - time.Second), StateReady},
		{"older_than_max_age", written.Add(ReadyMaxAge + time.Second), StateUnknown},
		{"clock_stepped_back_past_max_age", written.Add(-ReadyMaxAge - time.Second), StateUnknown},
	} {
		if got := ReadCurrentState(path, tc.now); got != tc.want {
			t.Errorf("%s: ReadCurrentState = %q, want %q", tc.name, got, tc.want)
		}
	}
	// ReadState keeps its age-free contract for callers that only need the
	// literal.
	if got := ReadState(path); got != StateReady {
		t.Fatalf("ReadState = %q, want ready", got)
	}

	// Re-publishing refreshes the age.
	old := written.Add(-2 * ReadyMaxAge)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	if got := ReadCurrentState(path, time.Now()); got != StateUnknown {
		t.Fatalf("aged ready = %q, want unknown", got)
	}
	if err := WriteState(path, StateReady); err != nil {
		t.Fatal(err)
	}
	if got := ReadCurrentState(path, time.Now()); got != StateReady {
		t.Fatalf("re-published ready = %q, want ready", got)
	}
}

func TestReadCurrentStateWaitingIsAgeIndependent(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	if err := WriteState(path, StateWaitingForTargets); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * ReadyMaxAge)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	if got := ReadCurrentState(path, time.Now()); got != StateWaitingForTargets {
		t.Fatalf("aged waiting_for_targets = %q, want waiting_for_targets", got)
	}
	if got := ReadCurrentState(filepath.Join(t.TempDir(), FileName), time.Now()); got != StateUnknown {
		t.Fatalf("missing file = %q, want unknown", got)
	}
	if got := ReadCurrentState(t.TempDir(), time.Now()); got != StateUnknown {
		t.Fatalf("directory = %q, want unknown", got)
	}
}
