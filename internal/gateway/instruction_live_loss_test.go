// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strings"
	"testing"
)

// livePressures are the two ways newer sessions fill a bounded loss list:
// by its entries (a full list's worth of newer lost sessions, with a call
// of the session halfway), and by its bytes (newer sessions whose first
// sighting proved many files).
var livePressures = []string{"entries", "bytes"}

// bulkIdentities is a large proof: the bytes pressure.
var bulkIdentities = strings.Split(strings.TrimSuffix(strings.Repeat("abcdef:0123456,", 200), ","), ",")

// Benign corpus (round q loop 2, live provenance at the pruned index
// bounds), with protected-target controls. A session the store pruned
// keeps its loss while it lives: a call of it makes it the newest entry of
// the pruned index, so a full index's worth of newer pruned sessions does
// not drop it, and past the index's byte bound it keeps its name (still
// lost) when what it proved no longer fits. Its next call never takes a
// new first sighting, so the AGENTS.md it created stays its own (default
// and permissive warn, strict blocks on existence), in the same process and
// after a restart; an AGENTS.md that existed before it still blocks by
// identity in every tier.
func TestInstructionBenignLivePrunedSessionKeepsItsLossAtTheIndexBounds(t *testing.T) {
	for _, tier := range instructionExistenceTiers {
		for _, pressure := range livePressures {
			for _, existed := range []bool{false, true} {
				if existed && pressure == "bytes" {
					continue // the oldest entries' identities give way to the byte bound
				}
				for _, restart := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s, %s, existed %v, restart %v", tier.pack, pressure, existed, restart), func(t *testing.T) {
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
						edit := func(label string) {
							t.Helper()
							got := s.patch(s.base, sightingUpdatePatch)
							checkExistenceTier(t, tier.blocks || existed, label, got.Action, got.Findings, "COG-AGENTS-MD")
						}
						edit("edit after the store pruned the session")
						fill := func(from, count int, proved []string) {
							cache := &api.activeAgentContext
							cache.storeMu.Lock()
							defer cache.storeMu.Unlock()
							cache.loadPrunedLocked(api.instructionLoadDir())
							for index := range count {
								cache.addPrunedLocked(fmt.Sprintf("%064x", 1<<40+from+index), proved)
							}
							cache.writePrunedLocked(api.instructionLoadDir())
						}
						if pressure == "entries" {
							fill(0, maxInstructionLoadPruned/2+1, nil)
							edit("edit with half an index of newer pruned sessions")
							fill(maxInstructionLoadPruned, maxInstructionLoadPruned/2, nil)
						} else {
							fill(0, maxInstructionLoadPrunedBytes/(15*len(bulkIdentities))+64, bulkIdentities)
						}
						if restart {
							api = fresh()
						}
						for range 2 {
							edit("edit after a full index of newer pruned sessions")
						}
					})
				}
			}
		}
	}
}

// Benign corpus (round q loop 2, live provenance at the lost set's
// bounds), with protected-target controls. A gateway without a data
// directory keeps a lost first sighting in memory: a call of the session
// makes it the newest lost session, so a full lost set's worth of newer
// unsaved evictions does not forget it, and past the set's byte bound it
// keeps its key (still lost). The AGENTS.md it created stays its own; one
// that existed before it still blocks by identity.
func TestInstructionBenignLiveUnsavedSessionKeepsItsLossAtTheSetBounds(t *testing.T) {
	for _, tier := range instructionExistenceTiers {
		for _, pressure := range livePressures {
			for _, existed := range []bool{false, true} {
				if existed && pressure == "bytes" {
					continue
				}
				t.Run(fmt.Sprintf("%s, %s, existed %v", tier.pack, pressure, existed), func(t *testing.T) {
					s := newManagedHiddenHomeSession(t, false)
					api := instructionProtectionTierTestAPI(t, "codex", tier.pack)
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
					edit := func(label string) {
						t.Helper()
						got := s.patch(s.base, sightingUpdatePatch)
						checkExistenceTier(t, tier.blocks || existed, label, got.Action, got.Findings, "COG-AGENTS-MD")
					}
					edit("edit after the unsaved session was evicted")
					fill := func(from, count int, proved []string) {
						cache := &api.activeAgentContext
						cache.mu.Lock()
						defer cache.mu.Unlock()
						for index := range count {
							key, _ := validActiveAgentContextKey("codex", fmt.Sprintf("other-%d", from+index))
							cache.rememberLostLocked(key, proved)
						}
					}
					if pressure == "entries" {
						fill(0, maxInstructionLoadPruned/2+1, nil)
						edit("edit with half a set of newer lost sessions")
						fill(maxInstructionLoadPruned, maxInstructionLoadPruned/2, nil)
					} else {
						fill(0, maxInstructionLostBytes/(15*len(bulkIdentities))+64, bulkIdentities)
					}
					for range 2 {
						edit("edit after a full set of newer lost sessions")
					}
				})
			}
		}
	}
}
