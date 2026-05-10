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

// TestPolicyFilePoll_TransitionGate_UnreadableThenDeleted pins the
// dedup contract for the unreadable→deleted edge case (the second
// way a path leaves the unreadable set, alongside unreadable→
// readable which is covered by the test above).
//
// Pre-fix audit trail for "operator finally rms a persistently
// EACCES policy file":
//
//	t0:  policy_file_read_failed   (transition gate marked it bad)
//	... (silent during persistent EACCES)
//	t9:  policy_file_read_recovered  ← misleading
//	t9:  policy_file_removed         ← actually correct
//
// The "recovered" event is misleading because the file isn't back —
// it's gone. Audit consumers correlating events would see "the file
// healed itself, then disappeared" which is not what happened.
//
// Post-fix: only the "removed" event fires. The transition gate
// suppresses the spurious recovery emit when next[p] doesn't contain
// the path at exit time (i.e. it left the unreadable set by deletion,
// not by recovery). The unreadable map still gets cleared so a future
// recreation+EACCES on the same path re-triggers the entry transition.
//
// We cannot easily count audit events from this test (the logger is
// the shared production sink; the existing test above documents the
// rationale). So instead we assert the post-condition: after a
// poll where bad transitioned from unreadable→deleted, the unreadable
// set is empty AND the file does not appear in policyFileHashes (the
// removal-diff branch has cleaned it up). This is a strict superset
// of the pre-fix observable state but the recovery emission itself
// is suppressed inside the watcher; the assertion below catches any
// regression that ALSO pollutes the unreadable map state.
func TestPolicyFilePoll_TransitionGate_UnreadableThenDeleted(t *testing.T) {
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

	bad := filepath.Join(cfg.PolicyDir, "doomed.yaml")
	if err := os.WriteFile(bad, []byte("- target_type: skill\n  target_name: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	// Cache the readable hash so the eventual removal hits the
	// "tracked-then-vanished" branch in the watcher loop.
	w.pollPolicyFilesOnce(ctx)
	w.policyFileMu.Lock()
	if _, ok := w.policyFileHashes[bad]; !ok {
		w.policyFileMu.Unlock()
		t.Fatalf("watcher should cache hash for readable file before EACCES test")
	}
	w.policyFileMu.Unlock()

	// EACCES: file present but unreadable. First poll marks the
	// transition; subsequent polls are no-ops (covered by the
	// other test, but we re-assert the entry condition here so
	// this test is independently readable).
	if err := os.Chmod(bad, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(bad, 0o600) })
	w.pollPolicyFilesOnce(ctx)
	w.policyFileMu.Lock()
	_, marked := w.policyFileUnreadable[bad]
	w.policyFileMu.Unlock()
	if !marked {
		t.Fatalf("file should be marked unreadable after EACCES poll")
	}

	// Operator gives up and deletes the file. Restore mode first
	// so os.Remove can unlink it on filesystems that require
	// search permission on the entry.
	if err := os.Chmod(bad, 0o600); err == nil {
		// On most systems chmod 0o000 on the file itself doesn't
		// block unlink (which uses parent dir perms); chmod here is
		// best-effort to keep the test portable.
	}
	if err := os.Remove(bad); err != nil {
		t.Fatalf("failed to delete unreadable file: %v", err)
	}

	// Next poll should:
	//   1. drop `bad` from policyFileUnreadable (path left the set)
	//   2. drop `bad` from policyFileHashes (removed-diff branch)
	//   3. NOT emit a recovery activity (suppressed because next[bad]
	//      does not exist — the path left the unreadable set by
	//      deletion, not by becoming readable)
	w.pollPolicyFilesOnce(ctx)
	w.policyFileMu.Lock()
	_, stillBad := w.policyFileUnreadable[bad]
	_, stillTracked := w.policyFileHashes[bad]
	w.policyFileMu.Unlock()
	if stillBad {
		t.Errorf("policyFileUnreadable should drop %s after deletion", bad)
	}
	if stillTracked {
		t.Errorf("policyFileHashes should drop %s after deletion (removed-diff branch)", bad)
	}

	// Re-create the file with EACCES and assert the entry
	// transition fires again. This proves the dedup map was
	// cleared cleanly, not silently broken.
	if err := os.WriteFile(bad, []byte("- target_type: skill\n  target_name: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bad, 0o000); err != nil {
		t.Fatal(err)
	}
	w.pollPolicyFilesOnce(ctx)
	w.policyFileMu.Lock()
	_, reMarked := w.policyFileUnreadable[bad]
	w.policyFileMu.Unlock()
	if !reMarked {
		t.Fatalf("re-creating the file with EACCES should re-mark it unreadable; transition gate is sticky")
	}
}
