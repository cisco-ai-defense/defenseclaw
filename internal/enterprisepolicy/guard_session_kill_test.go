// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"os"
	"testing"
	"time"
)

// publishedSessionKillTestBlock is a session-start scan that found an
// unapproved hook: the session and its agent process are blocked.
func publishedSessionKillTestBlock() GuardDecision {
	return GuardDecision{
		Deny:     true,
		Reason:   foreignHookBlockedPrefix + " the project file /repo/.github/hooks/x.json defines a hook.",
		Findings: []Finding{{Connector: "copilot", Scope: ScopeProject, Path: "/repo/.github/hooks/x.json", Event: "preToolUse", Digest: "abcd"}},
	}
}

// Kill switch (round 2 and 3 scenarios): the gateway records a block in its
// private store before it publishes it. A gateway that stopped between the
// two, or whose publication failed, left the earlier allow: with the hook
// file removed, the outage scan was clean and the hook honored it, while
// the gateway, once back, denies from its store. The gateway now removes
// the record key right before the first write of a block
// (SessionUpdate.BeforeBlock, RevokePublishedSessionKey), for each way a
// block is recorded:
//   - a session start that finds an unapproved hook;
//   - a block carried from a blocked session to the agent process that
//     calls in it (its own allow was published earlier);
//
// and an exchange that records no block kills nothing.
func TestApplyForeignHookSessionKillsTheKeyBeforeItRecordsABlock(t *testing.T) {
	root := publishedSessionTestRoot(t)
	identity := publishedSessionTestIdentity(t)
	stateDir := t.TempDir()
	kills := 0
	// blockedInStore is which of the key's private records are blocked.
	blockedInStore := func(key SessionKey) [2]bool {
		t.Helper()
		var blocked [2]bool
		for i, entry := range []struct{ kind, id string }{{sessionKindProcess, key.Process}, {sessionKindSession, key.Session}} {
			record, exists, err := readSessionRecord(sessionPathInDir(stateDir, key.Connector, entry.kind, entry.id))
			if err != nil {
				t.Fatal(err)
			}
			blocked[i] = exists && record.Blocked
		}
		return blocked
	}
	apply := func(key SessionKey, start bool, decision GuardDecision, publish bool) GuardDecision {
		t.Helper()
		before := blockedInStore(key)
		got := ApplyForeignHookSession(SessionUpdate{
			StateDir: stateDir, Key: key, SessionStart: start, Decision: decision, Now: time.Now(),
			BeforeBlock: func() {
				kills++
				if blockedInStore(key) != before {
					t.Error("the block must not be in the store before the key is removed")
				}
				if err := RevokePublishedSessionKey(root, identity); err != nil {
					t.Errorf("kill: %v", err)
				}
			},
		})
		if publish {
			if err := publishCurrent(root, identity, key, got, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
		return got
	}
	newKey := func() {
		t.Helper()
		if err := EnsurePublishedSessionKey(root, identity, publishedSessionTestTrust); err != nil {
			t.Fatal(err)
		}
	}

	// A session start that finds an unapproved hook, in a process whose
	// earlier session was allowed.
	first := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
	if got := apply(first, true, GuardDecision{}, true); got.Deny || kills != 0 || !publishedSessionTestAllows(root, identity, first) {
		t.Fatalf("a clean session start is allowed, kills nothing and is proven: %+v %d", got, kills)
	}
	again := SessionKey{Connector: "copilot", Session: "s-2", Process: "p-1"}
	// The gateway stops after the block is in its store, before it is
	// published, and the guardian makes a new key before the outage.
	if got := apply(again, true, publishedSessionKillTestBlock(), false); !got.Deny || kills != 1 {
		t.Fatalf("the session start that found the hook is blocked once the key is gone: %+v %d", got, kills)
	}
	newKey()
	for _, key := range []SessionKey{first, again} {
		if publishedSessionTestAllows(root, identity, key) {
			t.Fatalf("%+v: an allow the unpublished block overrules must prove nothing during the outage", key)
		}
	}
	if got := apply(again, false, GuardDecision{}, false); !got.Deny {
		t.Fatalf("the gateway, back, denies from its store: %+v", got)
	}

	// A session blocked in one agent process, resumed by another process
	// that was allowed in a session of its own: the block is carried to
	// that process.
	blocked := SessionKey{Connector: "copilot", Session: "s-3", Process: "p-0"}
	apply(blocked, true, publishedSessionKillTestBlock(), true)
	newKey()
	other := SessionKey{Connector: "copilot", Session: "s-4", Process: "p-2"}
	kills = 0
	if got := apply(other, true, GuardDecision{}, true); got.Deny || kills != 0 || !publishedSessionTestAllows(root, identity, other) {
		t.Fatalf("the other process is allowed in its own session: %+v %d", got, kills)
	}
	resumed := SessionKey{Connector: "copilot", Session: "s-3", Process: "p-2"}
	if got := apply(resumed, false, GuardDecision{}, false); !got.Deny || kills != 1 {
		t.Fatalf("a call in the blocked session carries the block to the process, once the key is gone: %+v %d", got, kills)
	}
	newKey()
	if publishedSessionTestAllows(root, identity, other) || publishedSessionTestAllows(root, identity, resumed) {
		t.Fatal("the process's earlier allow must prove nothing once the carried block is recorded, published or not")
	}
}

// Review P1 (round 3 scenario 1, kept): removals that cannot be read (the
// account's pending mark, a ledger that fails its check, a record folder
// the gateway cannot locate) deny the call but do not skip the session
// state: a session start that found an unapproved hook still records its
// block, after BeforeBlock removed the key, and the block is carried to the
// other key, while a call the removals alone deny writes nothing.
func TestApplyForeignHookSessionRecordsABlockWhileTheRemovalsCannotBeRead(t *testing.T) {
	for name, removalsErr := range map[string]error{
		"a removal in progress":   ErrForeignHookRemovalPending,
		"untrusted ledger":        errors.New("the removal ledger fails its trust check"),
		"record folder not found": errors.New("the protected foreign-hook session record folder cannot be located"),
	} {
		t.Run(name, func(t *testing.T) {
			stateDir := t.TempDir()
			kills := 0
			apply := func(key SessionKey, start bool, decision GuardDecision, err error) GuardDecision {
				t.Helper()
				return ApplyForeignHookSession(SessionUpdate{
					StateDir: stateDir, Key: key, SessionStart: start, Decision: decision, RemovalsErr: err, Now: time.Now(),
					BeforeBlock: func() { kills++ },
				})
			}
			key := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-1"}
			if got := apply(key, false, GuardDecision{}, removalsErr); !got.Deny {
				t.Fatalf("removals that cannot be read deny the call: %+v", got)
			}
			if entries, err := os.ReadDir(stateDir); err != nil || len(entries) != 0 {
				t.Fatalf("a call the removals alone deny writes nothing: %v %v", entries, err)
			}
			if got := apply(key, true, publishedSessionKillTestBlock(), removalsErr); !got.Deny || kills != 1 {
				t.Fatalf("the session start that found the hook records its block after the kill (%d): %+v", kills, got)
			}
			// The removals can be read again and the hook file is gone.
			if got := apply(key, false, GuardDecision{}, nil); !got.Deny {
				t.Fatalf("the session the start blocked stays blocked: %+v", got)
			}
			// Another agent process resumes the blocked session while the
			// removals cannot be read: the block is carried to it.
			kills = 0
			resumed := SessionKey{Connector: "copilot", Session: "s-1", Process: "p-2"}
			if got := apply(resumed, false, GuardDecision{}, removalsErr); !got.Deny || kills != 1 {
				t.Fatalf("the block is carried to the resuming process after the kill (%d): %+v", kills, got)
			}
			if got := apply(SessionKey{Connector: "copilot", Session: "s-9", Process: "p-2"}, false, GuardDecision{}, nil); !got.Deny {
				t.Fatalf("the carried block holds the process in its other sessions: %+v", got)
			}
		})
	}
}
