// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
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
	if err != nil || !strings.Contains(string(index), instructionLoadRecordName(key)) {
		t.Fatalf("the pruned index does not list the session: %v %q", err, index)
	}
}

// Benign corpus (T12b review loop round 2, store bound), with a
// protected-target control. A session whose saved record the store bound
// pruned has lost its first sighting: its next call takes no new one, so
// the AGENTS.md it created never becomes one that was there before it
// (default and permissive warn, strict blocks on existence, as without a
// snapshot), in the same gateway process and after a restart. An AGENTS.md
// that existed before the session is still proved by the identity the
// pruned index keeps: it blocks COG-AGENTS-MD in every tier, as with the
// record (round q: a lost first sighting never turns a pre-existing file
// into a warning). A new start of the session takes a new snapshot again. (Behind ProtectHome a session without a snapshot is
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
						checkExistenceTier(t, tier.blocks || existed, "edit after the store pruned the session", got.Action, got.Findings, "COG-AGENTS-MD")
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
		for _, existed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, existed %v", tier.pack, existed), func(t *testing.T) {
				testUnsavedFirstSightingEviction(t, tier.pack, tier.blocks, existed)
			})
		}
	}
}

// testUnsavedFirstSightingEviction: an AGENTS.md the session created warns
// (blocks in strict); one that existed before it blocks in every tier, by
// the identity the lost first sighting keeps.
func testUnsavedFirstSightingEviction(t *testing.T, pack string, blocks, existed bool) {
	s := newManagedHiddenHomeSession(t, false)
	api := instructionProtectionTierTestAPI(t, "codex", pack)
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
	churnInstructionSessions(t, s, maxActiveAgentContextSessions+8)
	key, _ := instructionStartupKey(withManagedHookPeer(t.Context(), managedHookPeer{}), "codex", "live")
	if _, cached := api.activeAgentContext.sessionKey(key); cached {
		t.Fatal("the churn did not evict the session from the cache")
	}
	for range 2 {
		got := s.patch(s.base, sightingUpdatePatch)
		checkExistenceTier(t, blocks || existed, "edit after the unsaved session was evicted", got.Action, got.Findings, "COG-AGENTS-MD")
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
	lost := len(api.activeAgentContext.lost)
	api.activeAgentContext.mu.Unlock()
	if lost != 0 {
		t.Fatalf("saved sessions were counted as lost: %d", lost)
	}
}

// Protected-target corpus (round q). A loss belongs to the session that
// owned it: past their entry bounds the pruned index and the lost set drop
// their least recently used entry (that session takes a new first
// sighting, which protects every file there then), and an unreadable index
// is taken as empty. No
// bound or read failure stops another session from taking its first
// sighting, so a late-start session's pre-existing AGENTS.md is never
// turned into a warning. The index keeps each entry's identities across a
// restart.
func TestInstructionPrunedIndexDropsOnlyTheOldest(t *testing.T) {
	dir := t.TempDir()
	lines := make([]string, 0, maxInstructionLoadPruned+1)
	for index := range maxInstructionLoadPruned + 1 {
		lines = append(lines, fmt.Sprintf("%064x", index))
	}
	lines[len(lines)-1] += " 10:20,xyz,30:40"
	if err := os.WriteFile(filepath.Join(dir, instructionLoadPrunedName), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var cache activeAgentContextCache
	cache.storeMu.Lock()
	cache.loadPrunedLocked(dir)
	cache.storeMu.Unlock()
	if _, oldest := cache.pruned[fmt.Sprintf("%064x", 0)]; oldest || len(cache.pruned) != maxInstructionLoadPruned {
		t.Fatalf("an index past its bound kept %d entries (oldest kept %v)", len(cache.pruned), oldest)
	}
	if got := cache.pruned[fmt.Sprintf("%064x", maxInstructionLoadPruned)]; !slices.Equal(got, []string{"10:20", "30:40"}) {
		t.Fatalf("the newest entry's identities = %v", got)
	}
	cache.storeMu.Lock()
	cache.writePrunedLocked(dir)
	cache.storeMu.Unlock()
	var reread activeAgentContextCache
	reread.storeMu.Lock()
	reread.loadPrunedLocked(dir)
	reread.storeMu.Unlock()
	if len(reread.pruned) != maxInstructionLoadPruned || !slices.Equal(reread.prunedOrder, cache.prunedOrder) {
		t.Fatal("the index did not read back as written")
	}
	_ = os.Remove(filepath.Join(dir, instructionLoadPrunedName))
	if err := os.WriteFile(filepath.Join(dir, instructionLoadPrunedName), []byte(fmt.Sprintf("%064x\n", 1)), 0o000); err != nil {
		t.Fatal(err)
	}
	// Windows file modes do not deny reads, and root reads every file.
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		var unreadable activeAgentContextCache
		unreadable.storeMu.Lock()
		unreadable.loadPrunedLocked(dir)
		unreadable.storeMu.Unlock()
		if len(unreadable.pruned) != 0 {
			t.Fatal("an unreadable index listed sessions")
		}
	}
	// The lost set drops its least recently used entry past its entry
	// bound, and a session that lost nothing still takes its first
	// sighting.
	var lost activeAgentContextCache
	lost.mu.Lock()
	for index := range maxInstructionLoadPruned + 1 {
		key, _ := validActiveAgentContextKey("codex", fmt.Sprintf("lost-%d", index))
		lost.rememberLostLocked(key, nil)
	}
	lost.mu.Unlock()
	first, _ := validActiveAgentContextKey("codex", "lost-0")
	if _, kept := lost.lostKey(first); kept {
		t.Fatal("the lost set kept its oldest entry past its bound")
	}
	fresh, _ := validActiveAgentContextKey("codex", "fresh")
	if !lost.firstSightingKey(fresh, map[string]string{}, []string{"/w"}, nil) {
		t.Fatal("a full lost set stopped another session's first sighting")
	}
}

// Protected-target corpus (round q). A late-start Codex session that sent
// no startup evidence takes its first sighting even after another session's
// record was pruned and the store's index is unreadable: its pre-existing
// AGENTS.md blocks in default.
func TestInstructionLateStartSessionIsNotLostByAnotherSession(t *testing.T) {
	s := newManagedHiddenHomeSession(t, false)
	dataDir := t.TempDir()
	api := instructionProtectionTierTestAPI(t, "codex", "default")
	api.scannerCfg.DataDir = dataDir
	s.gateway = func() *APIServer { return api }
	s.start(true)
	pruneInstructionSession(t, s, api)
	if err := os.WriteFile(filepath.Join(api.instructionLoadDir(), instructionLoadPrunedName), []byte("*\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	restarted := instructionProtectionTierTestAPI(t, "codex", "default")
	restarted.scannerCfg.DataDir = dataDir
	s.gateway = func() *APIServer { return restarted }
	other := filepath.Join(s.home, "other")
	writeActiveAgentTestFile(t, other, "AGENTS.md")
	input := map[string]interface{}{"command": "printf x >> AGENTS.md"}
	got := s.judge(instructionResolvedWriteContext(t, other, "Bash", input), codexHookRequest{
		HookEventName: "PreToolUse", SessionID: "late", CWD: other, ToolName: "Bash", ToolInput: input,
	})
	if got.Action != guardrailActionBlock || !findingStringHasRuleID(got.Findings, "COG-AGENTS-MD") {
		t.Fatalf("another session's lost first sighting weakened a late start: %+v", got)
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
