// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// pruneInstructionSession fills the store past its record bound with newer
// records, so the next save prunes the record of "live" (the oldest), and
// evicts "live" from the in-memory cache.
func pruneInstructionSession(t *testing.T, s *managedHiddenHomeSession, api *APIServer) {
	t.Helper()
	dir := api.instructionLoadDir()
	key, _ := instructionStartupKey(withManagedHookPeer(t.Context(), managedHookPeer{}), "codex", "live")
	record := instructionLoadRecordPath(dir, key)
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(record, old, old); err != nil {
		t.Fatalf("the session has no saved record: %v", err)
	}
	for index := range maxInstructionLoadRecords {
		name := filepath.Join(dir, fmt.Sprintf("%064x.json", index+1))
		if err := os.WriteFile(name, []byte(`{"startup_known":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	churnInstructionSessions(t, s, maxActiveAgentContextSessions+8)
	if _, err := os.Lstat(record); !os.IsNotExist(err) {
		t.Fatalf("the store kept the oldest record past its bound: %v", err)
	}
	if _, cached := api.activeAgentContext.sessionKey(key); cached {
		t.Fatal("the churn did not evict the session from the cache")
	}
	index, err := os.ReadFile(filepath.Join(dir, instructionLoadPrunedName))
	if err != nil || !strings.Contains(string(index), instructionLoadRecordName(key)+"\n") {
		t.Fatalf("the pruned index does not list the session: %v %q", err, index)
	}
}

// Benign corpus (T12b review loop round 2, store bound), with a
// protected-target control. A session whose saved record the store bound
// pruned has lost its first sighting: its next call takes no new one, so
// the AGENTS.md it created never becomes one that was there before it
// (default and permissive warn, strict blocks on existence, as without a
// snapshot), in the same gateway process and after a restart. An AGENTS.md
// that existed before the session keeps its COG-AGENTS-MD finding in every
// tier and blocks in strict. A new start of the session takes a new
// snapshot again. (Behind ProtectHome a session without a snapshot is
// judged by the call-time proof of every rule, as a 1.0.3 hook's is; that
// is not this test's subject.)
func TestInstructionBenignPrunedFirstSightingNeverProvesPreexisting(t *testing.T) {
	for _, tier := range instructionExistenceTiers {
		for _, restart := range []bool{false, true} {
			for _, existed := range []bool{false, true} {
				name := fmt.Sprintf("%s, restart %v, existed %v", tier.pack, restart, existed)
				t.Run(name, func(t *testing.T) {
					s := newManagedHiddenHomeSession(t, false)
					dataDir := t.TempDir()
					fresh := func() *APIServer {
						api := instructionProtectionTierTestAPI(t, "codex", tier.pack)
						api.scannerCfg.DataDir = dataDir
						return api
					}
					api := fresh()
					s.gateway = func() *APIServer { return api }
					if existed {
						writeActiveAgentTestFile(t, s.base, "AGENTS.md")
					}
					s.start(true)
					if !existed {
						if got := s.patch(s.base, sightingAddPatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
							t.Fatalf("creating AGENTS.md was blocked: %+v", got)
						}
						writeActiveAgentTestFile(t, s.base, "AGENTS.md")
					}
					pruneInstructionSession(t, s, api)
					if restart {
						api = fresh()
					}
					for range 2 {
						got := s.patch(s.base, sightingUpdatePatch)
						checkExistenceTier(t, tier.blocks, "edit after the store pruned the session", got.Action, got.Findings, "COG-AGENTS-MD")
					}
					// A new start of the session takes its own snapshot:
					// the AGENTS.md there now is protected again.
					s.start(true)
					if got := s.patch(s.base, sightingUpdatePatch); got.Action != guardrailActionBlock || !findingStringHasRuleID(got.Findings, "COG-AGENTS-MD") {
						t.Fatalf("a new start did not protect the AGENTS.md there at its start: %+v", got)
					}
					index, _ := os.ReadFile(filepath.Join(api.instructionLoadDir(), instructionLoadPrunedName))
					key, _ := instructionStartupKey(withManagedHookPeer(t.Context(), managedHookPeer{}), "codex", "live")
					if strings.Contains(string(index), instructionLoadRecordName(key)) {
						t.Fatal("a new start left the session in the pruned index")
					}
				})
			}
		}
	}
}

// Benign corpus (T12b review loop round 2, no saved record). A gateway
// without a data directory saves no record: a session the cache evicts
// loses its first sighting, and its next call takes no new one, so the
// AGENTS.md it created stays its own.
func TestInstructionBenignUnsavedFirstSightingEvictionNeverProvesPreexisting(t *testing.T) {
	for _, tier := range instructionExistenceTiers {
		t.Run(tier.pack, func(t *testing.T) {
			s := newManagedHiddenHomeSession(t, false)
			api := instructionProtectionTierTestAPI(t, "codex", tier.pack)
			s.gateway = func() *APIServer { return api }
			s.start(true)
			if got := s.patch(s.base, sightingAddPatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
				t.Fatalf("creating AGENTS.md was blocked: %+v", got)
			}
			writeActiveAgentTestFile(t, s.base, "AGENTS.md")
			churnInstructionSessions(t, s, maxActiveAgentContextSessions+8)
			key, _ := instructionStartupKey(withManagedHookPeer(t.Context(), managedHookPeer{}), "codex", "live")
			if _, cached := api.activeAgentContext.sessionKey(key); cached {
				t.Fatal("the churn did not evict the session from the cache")
			}
			for range 2 {
				got := s.patch(s.base, sightingUpdatePatch)
				checkExistenceTier(t, tier.blocks, "edit after the unsaved session was evicted", got.Action, got.Findings, "COG-AGENTS-MD")
			}
		})
	}
}

// The saved flag follows the store: a session the store holds is not lost
// when the cache evicts it, so a churned session with a record restores its
// own first sighting (TestInstructionBenignFirstSightingSurvivesCacheChurn)
// and is not counted against the lost bound.
func TestInstructionSavedSessionEvictionIsNotLost(t *testing.T) {
	s := newManagedHiddenHomeSession(t, false)
	api := s.gateway()
	s.gateway = func() *APIServer { return api }
	s.start(true)
	churnInstructionSessions(t, s, maxActiveAgentContextSessions+8)
	api.activeAgentContext.mu.Lock()
	lost, all := len(api.activeAgentContext.lost), api.activeAgentContext.lostAll
	api.activeAgentContext.mu.Unlock()
	if lost != 0 || all {
		t.Fatalf("saved sessions were counted as lost: %d %v", lost, all)
	}
}

// The pruned index past its bound, or unreadable, takes every session the
// gateway does not hold as pruned; it never drops a pruned session.
func TestInstructionPrunedIndexSaturates(t *testing.T) {
	dir := t.TempDir()
	lines := make([]string, 0, maxInstructionLoadPruned+1)
	for index := range maxInstructionLoadPruned + 1 {
		lines = append(lines, fmt.Sprintf("%064x", index))
	}
	if err := os.WriteFile(filepath.Join(dir, instructionLoadPrunedName), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var cache activeAgentContextCache
	cache.storeMu.Lock()
	cache.loadPrunedLocked(dir)
	cache.storeMu.Unlock()
	if !cache.prunedAll {
		t.Fatal("an index past its bound did not take every session as pruned")
	}
	_ = os.Remove(filepath.Join(dir, instructionLoadPrunedName))
	if err := os.WriteFile(filepath.Join(dir, instructionLoadPrunedName), []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	// Windows file modes do not deny reads, and root reads every file.
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		var unreadable activeAgentContextCache
		unreadable.storeMu.Lock()
		unreadable.loadPrunedLocked(dir)
		unreadable.storeMu.Unlock()
		if !unreadable.prunedAll {
			t.Fatal("an unreadable index did not take every session as pruned")
		}
	}
}

// Benign corpus (T12b review loop round 2, unreadable record). A session
// whose saved record is there but cannot be restored (invalid, or not a
// regular file) has lost its first sighting too: the AGENTS.md it created
// stays its own after an eviction or a restart.
func TestInstructionBenignInvalidRecordNeverProvesPreexisting(t *testing.T) {
	for _, tier := range instructionExistenceTiers {
		for _, restart := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, restart %v", tier.pack, restart), func(t *testing.T) {
				s := newManagedHiddenHomeSession(t, false)
				dataDir := t.TempDir()
				fresh := func() *APIServer {
					api := instructionProtectionTierTestAPI(t, "codex", tier.pack)
					api.scannerCfg.DataDir = dataDir
					return api
				}
				api := fresh()
				s.gateway = func() *APIServer { return api }
				s.start(true)
				if got := s.patch(s.base, sightingAddPatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
					t.Fatalf("creating AGENTS.md was blocked: %+v", got)
				}
				writeActiveAgentTestFile(t, s.base, "AGENTS.md")
				churnInstructionSessions(t, s, maxActiveAgentContextSessions+8)
				key, _ := instructionStartupKey(withManagedHookPeer(t.Context(), managedHookPeer{}), "codex", "live")
				if err := os.WriteFile(instructionLoadRecordPath(api.instructionLoadDir(), key), []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
				if restart {
					api = fresh()
				}
				for range 2 {
					got := s.patch(s.base, sightingUpdatePatch)
					checkExistenceTier(t, tier.blocks, "edit after the record became invalid", got.Action, got.Findings, "COG-AGENTS-MD")
				}
			})
		}
	}
}
