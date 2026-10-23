// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// GAP-1130: at the bound, the identity.observed throttle keeps its recent
// users instead of forgetting all of them, and a user seen for the first time
// still gets its record: the oldest mark makes room for it.
func TestIdentityObservedThrottleKeepsRecentUsersAtItsBound(t *testing.T) {
	identityObservedState.Lock()
	saved, savedPending := identityObservedState.last, identityObservedState.pending
	identityObservedState.last, identityObservedState.pending = map[string]identityObservedMark{}, map[string]bool{}
	identityObservedState.Unlock()
	t.Cleanup(func() {
		identityObservedState.Lock()
		identityObservedState.last, identityObservedState.pending = saved, savedPending
		identityObservedState.Unlock()
	})
	now := time.Now()
	facts := useridentity.DirectoryFacts{Domain: "corp.example"}
	for i := 0; i < identityObservedMaxUsers; i++ {
		finish, due := identityObservedBegin(fmt.Sprint(i), facts, now.Add(time.Duration(i)*time.Microsecond))
		if !due {
			t.Fatalf("user %d was not due", i)
		}
		finish(true)
	}
	finish, due := identityObservedBegin("overflow", facts, now.Add(time.Second))
	if !due {
		t.Fatal("the first identity.observed record of a user past the bound was suppressed")
	}
	finish(true)
	if _, due := identityObservedBegin("overflow", facts, now.Add(2*time.Second)); due {
		t.Fatal("the new user's record went out twice")
	}
	if n := len(identityObservedState.last); n > identityObservedMaxUsers {
		t.Fatalf("%d users remembered, past the bound %d", n, identityObservedMaxUsers)
	}
	recent := 0
	for i := 1; i < identityObservedMaxUsers; i++ {
		if _, due := identityObservedBegin(fmt.Sprint(i), facts, now.Add(3*time.Second)); !due {
			recent++
		}
	}
	if recent != identityObservedMaxUsers-1 {
		t.Fatalf("%d of %d recent users kept their mark; one new user let out more than one", recent, identityObservedMaxUsers-1)
	}
	if _, due := identityObservedBegin("0", facts, now.Add(3*time.Second)); !due {
		t.Fatal("the oldest mark was not the one dropped for the new user")
	}
}

// newProfileGroupSIDs is buildProfileGroupSIDs without a local-only lookup:
// bare names take the directory lane, as everywhere but on Windows.
func newProfileGroupSIDs(assignments []config.ProfileAssignment, lookup func(string) (string, error), wait time.Duration) *profileGroupSIDs {
	return buildProfileGroupSIDs(assignments, lookup, nil, wait)
}

// Review of GAP-1261: a bare group name is looked up among this computer's
// groups first, in the local lane, as the LSA reads a bare name, so a stalled
// domain controller does not keep a bare local group without its SID; a bare
// name that is no local group still goes to the directory once a slot frees.
func TestBareLocalGroupSIDResolvesWhileDirectoryLookupsStall(t *testing.T) {
	stalled := make(chan struct{})
	profileGroupSIDLookups.Lock()
	var keys []string
	for i := 0; len(profileGroupSIDLookups.calls)-profileGroupSIDLookups.local < profileGroupSIDLookupsMax; i++ {
		key := foldKey(fmt.Sprintf(`CORP\stalled-bare-%d`, i))
		profileGroupSIDLookups.calls[key] = &profileGroupSIDLookupCall{done: stalled}
		keys = append(keys, key)
	}
	profileGroupSIDLookups.Unlock()
	release := func() {
		profileGroupSIDLookups.Lock()
		for _, key := range keys {
			delete(profileGroupSIDLookups.calls, key)
		}
		keys = nil
		profileGroupSIDLookups.Unlock()
	}
	t.Cleanup(func() {
		release()
		close(stalled)
	})
	directory := func(name string) (string, error) { return "S-1-5-21-1-2-3-1105", nil }
	local := func(name string) (string, error) {
		if strings.EqualFold(name, "strict-users") {
			return "S-1-5-21-9-9-9-1001", nil
		}
		return "", errProfileGroupUnknown
	}
	assignments := []config.ProfileAssignment{{Profile: "strict", Match: config.ProfileMatch{Groups: []string{"strict-users", "ai-team"}}}}
	sids := buildProfileGroupSIDs(assignments, directory, local, time.Second)
	if sid, ok := sids.sid("strict-users"); !ok || sid != "S-1-5-21-9-9-9-1001" {
		t.Fatalf("bare local group while directory lookups stall: sid %q, %v", sid, ok)
	}
	if _, ok := sids.sid("ai-team"); ok {
		t.Fatal("a bare directory group resolved past the directory bound")
	}
	release()
	sids.refresh(time.Now(), true)
	if sid, ok := sids.sid("ai-team"); !ok || sid != "S-1-5-21-1-2-3-1105" {
		t.Fatalf("bare directory group once a slot freed: sid %q, %v", sid, ok)
	}
}

// GAP-1128: child-session exclusions stay within the sub-session bound
// while inventory writes keep failing.
func TestSubagentExclusionsStayBoundedAcrossFailedWrites(t *testing.T) {
	r := &agentIdentityRecorder{pending: map[string]*inventory.AgentIdentityRecord{}, hints: map[string]string{}}
	const agent = "agt-00000000000000a1"
	for i := 0; i < agentIdentityRecorderMaxPending+100; i++ {
		r.markSubagentSession(agent, fmt.Sprintf("child-%d", i))
	}
	if n := len(r.exclusions); n > agentIdentityRecorderMaxPending {
		t.Fatalf("%d exclusions buffered, past the bound %d", n, agentIdentityRecorderMaxPending)
	}
	for round := 0; round < 3; round++ {
		batch, excluded, subagents := r.take()
		for i := 0; i < 100; i++ {
			r.markSubagentSession(agent, fmt.Sprintf("child-%d-%d", round, i))
		}
		r.restore(batch, excluded, subagents) // the write failed
	}
	if n := len(r.exclusions); n > agentIdentityRecorderMaxPending {
		t.Fatalf("%d exclusions after failed writes, past the bound %d", n, agentIdentityRecorderMaxPending)
	}
	for key := range r.exclusions {
		if _, sub := r.subSessions[key]; !sub {
			t.Fatalf("exclusion %q outlived its sub-session", key)
		}
	}
	if _, kept := r.exclusions[subSessionKey(agent, "child-2-99")]; !kept {
		t.Fatal("the newest child link was lost")
	}
}

// GAP-1141, GAP-1144: on standalone Windows a group shown only by its SID
// still matches the assignment that names it, and the note says so.
func TestUnnamedSIDGroupsNoteAgreesWithSIDMatching(t *testing.T) {
	const team = "S-1-5-21-1-2-3-4100"
	sids := newProfileGroupSIDs([]config.ProfileAssignment{{Profile: "strict", Match: config.ProfileMatch{Groups: []string{`CORP\team`}}}},
		func(string) (string, error) { return team, nil }, time.Second)
	subject := &profileSubject{Groups: []string{team}}
	groups := &subjectGroups{sids: sids, list: subject.Groups}
	if !groups.has(`CORP\team`) {
		t.Fatal("the SID-only group does not match the assignment that names it")
	}
	note := unnamedGroupsNote(subject, sids)
	if strings.Contains(note, "cannot match") || !strings.Contains(note, "assignments match groups by SID") {
		t.Fatalf("note = %q; want it to agree with the SID match", note)
	}
	if note := unnamedGroupsNote(subject, nil); !strings.Contains(note, "cannot match") {
		t.Fatalf("note without SID matching = %q", note)
	}
}

// GAP-1142: status names a group as unresolved only until its lookup
// answers, without a hook call in between.
func TestGroupSIDWarningsTakeInAFinishedLookup(t *testing.T) {
	release := make(chan struct{})
	lookup := func(string) (string, error) { <-release; return "S-1-5-21-1-2-3-4200", nil }
	assignments := []config.ProfileAssignment{{Profile: "strict", Match: config.ProfileMatch{Groups: []string{`CORP\gap1142`}}}}
	sids := newProfileGroupSIDs(assignments, lookup, 10*time.Millisecond)
	if warnings := sids.warnings(assignments); len(warnings) != 1 {
		t.Fatalf("warnings while the lookup runs = %q", warnings)
	}
	sids.mu.Lock()
	call := sids.entries[foldKey(`CORP\gap1142`)].call
	sids.mu.Unlock()
	close(release)
	<-call.done
	if warnings := sids.warnings(assignments); len(warnings) != 0 {
		t.Fatalf("warnings after the lookup answered = %q", warnings)
	}
}

// GAP-1261: lookups a stalled directory holds do not keep a reload from
// resolving a group of this computer.
func TestLocalGroupSIDResolvesWhileDirectoryLookupsStall(t *testing.T) {
	previousDomain := profileGroupLocalDomain
	profileGroupLocalDomain = func() string { return "WS01" }
	stalled := make(chan struct{})
	profileGroupSIDLookups.Lock()
	var keys []string
	for i := 0; len(profileGroupSIDLookups.calls)-profileGroupSIDLookups.local < profileGroupSIDLookupsMax; i++ {
		key := foldKey(fmt.Sprintf(`CORP\stalled-%d`, i))
		profileGroupSIDLookups.calls[key] = &profileGroupSIDLookupCall{done: stalled}
		keys = append(keys, key)
	}
	profileGroupSIDLookups.Unlock()
	t.Cleanup(func() {
		profileGroupSIDLookups.Lock()
		for _, key := range keys {
			delete(profileGroupSIDLookups.calls, key)
		}
		profileGroupSIDLookups.Unlock()
		close(stalled)
		profileGroupLocalDomain = previousDomain
	})
	lookup := func(name string) (string, error) { return "S-1-5-21-9-9-9-1001", nil }
	for _, name := range []string{`WS01\strict-users`, `.\strict-users`, `BUILTIN\Users`} {
		sids := newProfileGroupSIDs([]config.ProfileAssignment{{Profile: "strict", Match: config.ProfileMatch{Groups: []string{name}}}}, lookup, time.Second)
		if sid, ok := sids.sid(name); !ok || sid != "S-1-5-21-9-9-9-1001" {
			t.Fatalf("local group %s while directory lookups stall: sid %q, %v", name, sid, ok)
		}
	}
	sids := newProfileGroupSIDs([]config.ProfileAssignment{{Profile: "strict", Match: config.ProfileMatch{Groups: []string{`CORP\other`}}}}, lookup, 50*time.Millisecond)
	if _, ok := sids.sid(`CORP\other`); ok {
		t.Fatal("a directory lookup started past its bound")
	}
}
