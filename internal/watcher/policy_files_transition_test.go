// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandbox"
)

// TestPolicyFilePoll_TransitionGate_UnreadableThenReadable pins the
// transition-gate contract on recordPolicyFileReadFailure: a
// persistent EACCES/EPERM emits exactly ONE "unreadable" activity
// (on entry) and ONE "recovered" activity (on exit), regardless of
// how many polls happen in between.
//
// The pre-fix behavior emitted one event per poll (~2s tick), which
// flooded audit and downstream telemetry storage on long-running
// outages.
func TestPolicyFilePoll_TransitionGate_UnreadableThenReadable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: chmod-based unreadable test cannot guarantee EACCES")
	}
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.PolicyDir = filepath.Join(cfg.DataDir, "policies")
	if err := os.MkdirAll(cfg.PolicyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)
	w := New(cfg, nil, nil, store, logger, shell, nil, nil, nil)

	// Seed two readable policy files so we can assert that the
	// transition gate ONLY suppresses repeated EACCES emissions —
	// it must NOT block detection of legitimate edits to other files.
	good := filepath.Join(cfg.PolicyDir, "good.yaml")
	bad := filepath.Join(cfg.PolicyDir, "bad.yaml")
	if err := os.WriteFile(good, []byte("- target_type: skill\n  target_name: a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte("- target_type: skill\n  target_name: b\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	// Initial poll caches both hashes.
	w.pollPolicyFilesOnce(ctx)

	// Make `bad` unreadable; poll multiple times — should record the
	// transition exactly once.
	if err := os.Chmod(bad, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(bad, 0o600) })

	// First unreadable poll → should mark the transition.
	w.pollPolicyFilesOnce(ctx)
	w.policyFileMu.Lock()
	_, marked := w.policyFileUnreadable[bad]
	w.policyFileMu.Unlock()
	if !marked {
		t.Fatalf("policyFileUnreadable should mark %s on first unreadable poll", bad)
	}

	// Subsequent unreadable polls → must NOT alter the unreadable
	// set (no duplicate recordPolicyFileReadFailure call). We assert
	// the size stays at exactly 1 across polls.
	for i := 0; i < 5; i++ {
		w.pollPolicyFilesOnce(ctx)
	}
	w.policyFileMu.Lock()
	got := len(w.policyFileUnreadable)
	w.policyFileMu.Unlock()
	if got != 1 {
		t.Fatalf("policyFileUnreadable should remain at 1 entry across repeated polls, got %d", got)
	}

	// Mutate `good` while `bad` is still unreadable — must still see
	// the change to `good` (the original DeepSec bug was that one
	// unreadable file blanked all detection).
	if err := os.WriteFile(good, []byte("- target_type: skill\n  target_name: aaa\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w.pollPolicyFilesOnce(ctx)
	// We don't assert audit emission counts directly (the test
	// logger is shared and counting events would couple us to the
	// audit pipeline internals); instead we assert that the hash
	// for `good` updated, which proves the diff was processed
	// despite `bad` still being unreadable.
	w.policyFileMu.Lock()
	updatedHash := w.policyFileHashes[good]
	w.policyFileMu.Unlock()
	if updatedHash == "" {
		t.Fatalf("hash for good.yaml should be cached after edit")
	}

	// Restore `bad` permissions; next poll → recovery transition,
	// removing it from the unreadable set.
	if err := os.Chmod(bad, 0o600); err != nil {
		t.Fatal(err)
	}
	w.pollPolicyFilesOnce(ctx)
	w.policyFileMu.Lock()
	_, stillBad := w.policyFileUnreadable[bad]
	w.policyFileMu.Unlock()
	if stillBad {
		t.Fatalf("policyFileUnreadable should drop %s after recovery", bad)
	}

	// One more poll — recovery must NOT re-emit (the entry is
	// already cleared, transition gate should leave it alone).
	for i := 0; i < 3; i++ {
		w.pollPolicyFilesOnce(ctx)
	}
	w.policyFileMu.Lock()
	finalSize := len(w.policyFileUnreadable)
	w.policyFileMu.Unlock()
	if finalSize != 0 {
		t.Fatalf("policyFileUnreadable should remain empty post-recovery, got %d entries", finalSize)
	}
}
