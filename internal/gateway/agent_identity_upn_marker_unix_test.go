// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// W19 review (loop round 2): on Linux and macOS the guardian can mark the
// UPN it verified as kept (infopipe_kept) without changing its text, or
// drop, rename or withdraw it, after the gateway cached facts that merged
// the verified record. A marker-only change does not refresh the policy
// cache, and profile matching must not change, but the agent identity row
// of every later hook lists only the UPN the guardian's current record
// verifies.
func TestAgentIdentityRowFollowsTheCurrentUnixGuardianRecord(t *testing.T) {
	const upn = "dcad-strict@dclab.test"
	verified := enterprisehooks.IdentitySpoolRecord{User: "dcad-strict", AccountSID: unixFactsSID,
		UPNSource: enterprisehooks.UPNSourceInfoPipe, Facts: useridentity.DirectoryFacts{
			UPN: upn, Principal: upn, Realm: "DCLAB.TEST", Directory: useridentity.DirectoryActiveDirectory}}
	keptRecord := func() enterprisehooks.IdentitySpoolRecord {
		record := verified
		record.UPNSource, record.UPNKeptSince = enterprisehooks.UPNSourceInfoPipeKept, time.Now().UTC()
		return record
	}
	for _, tc := range []struct {
		name string
		// change is the guardian's later pass, after the facts are cached.
		change func(write func(enterprisehooks.IdentitySpoolRecord), withdraw func(time.Time))
		// policyUnchanged: the change is one the policy cache does not act
		// on, so profile matching selects what it did.
		policyUnchanged bool
		// after is the UPN the row lists after the change ("" none).
		after string
		// recovers: a later verified record lists the UPN again.
		recovers bool
	}{
		{name: "verified UPN marked infopipe_kept", policyUnchanged: true, recovers: true,
			change: func(write func(enterprisehooks.IdentitySpoolRecord), _ func(time.Time)) { write(keptRecord()) }},
		{name: "verified UPN dated kept", policyUnchanged: true, recovers: true,
			change: func(write func(enterprisehooks.IdentitySpoolRecord), _ func(time.Time)) {
				record := verified
				record.UPNKeptSince = time.Now().UTC()
				write(record)
			}},
		{name: "kept UPN dropped", policyUnchanged: true,
			change: func(write func(enterprisehooks.IdentitySpoolRecord), _ func(time.Time)) {
				record := verified
				record.UPNSource, record.Facts.UPN, record.Facts.Principal = "", "", ""
				write(record)
			}},
		{name: "UPN renamed", after: "dcad-renamed@dclab.test",
			change: func(write func(enterprisehooks.IdentitySpoolRecord), _ func(time.Time)) {
				record := verified
				record.Facts.UPN, record.Facts.Principal = "dcad-renamed@dclab.test", "dcad-renamed@dclab.test"
				write(record)
			}},
		{name: "identity withdrawn",
			change: func(_ func(enterprisehooks.IdentitySpoolRecord), withdraw func(time.Time)) {
				if err := os.Remove(filepath.Join(currentIdentitySpoolDir(), unixFactsUID+".json")); err != nil {
					panic(err)
				}
				withdraw(time.Now())
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			agentIdentityTestSetup(t)
			writeRecord, withdraw := unixFactsSpool(t)
			decide := unixFactsProfiles(t)
			uid, _ := strconv.Atoi(unixFactsUID)
			previous, previousFacts := managedHookPeerHomes, identityFactsEnabled.Load()
			managedHookPeerHomes = &managedHookPeerHomeCache{
				newResolver: func() unixidentity.Resolver {
					return &fakePeerHomeResolver{accounts: map[int]unixidentity.Account{
						uid: {Name: "dcad-strict", UID: uid, Home: "/home/dcad-strict"},
					}}
				},
				now: time.Now,
			}
			setIdentityFactsEnabled(true)
			t.Cleanup(func() {
				managedHookPeerHomes = previous
				setIdentityFactsEnabled(previousFacts)
			})
			managedHookPeerHomes.directoriesOnce.Do(func() {
				// What resolveNSSPeerFacts does, with NSS answering no
				// group: only the UPN selects the strict profile.
				managedHookPeerHomes.directories = newIdentityDirectoryCache(func(key string) (useridentity.DirectoryFacts, error) {
					now := time.Now()
					facts := unixNSSFacts()
					facts.Groups = nil
					facts.SpoolSeenAt = identitySpoolSeenAt(key, now)
					if record, ok, err := readIdentitySpoolFactsForAccount(key, "dcad-strict", unixFactsSID, now); err != nil {
						return useridentity.DirectoryFacts{}, err
					} else if ok {
						facts = mergeSpoolFacts(facts, record)
					}
					return facts, nil
				})
			})
			store, err := inventory.NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			prev := sharedAgentIdentities
			sharedAgentIdentities = &agentIdentityRecorder{pending: map[string]*inventory.AgentIdentityRecord{}, hints: map[string]string{}}
			sharedAgentIdentities.setStoreSource(func() *inventory.InventoryStore { return store }, nil, nil)
			t.Cleanup(func() { sharedAgentIdentities = prev })

			home := t.TempDir()
			hook := func(name string) (row map[string]any, policy profileDecision) {
				t.Helper()
				// The hook path's own lookup (it runs forgetOnSpoolChange),
				// then the hook's agent identity sighting.
				facts, ok := managedHookPeerHomes.directory(uid, true)
				policy = decide(facts, ok)
				identity := agentIdentityForGenericHook(withManagedHookPeer(context.Background(),
					managedHookPeer{UID: uid, Name: "dcad-strict", Home: home}),
					agentHookRequest{ConnectorName: "codex", SessionID: "sess-" + name, HookEventName: "PreToolUse",
						Payload: map[string]interface{}{}})
				row = listedAgentIdentityRows(t)[identity.IdentityID]
				if row == nil {
					t.Fatalf("%s: no agent identity row", name)
				}
				return row, policy
			}

			writeRecord(verified)
			row, before := hook("verified")
			if row["upn"] != upn || before.Name != "strict" {
				t.Fatalf("verified record: row %v, profile %+v; want upn %s and strict", row, before, upn)
			}
			time.Sleep(time.Millisecond) // a pass written after the lookup
			tc.change(writeRecord, withdraw)
			for i := 1; i <= 3; i++ {
				row, policy := hook("changed-" + strconv.Itoa(i))
				if got, named := row["upn"]; (tc.after == "" && named) || (tc.after != "" && got != tc.after) {
					t.Fatalf("hook %d after the change: row lists upn %v; want %q", i, got, tc.after)
				}
				if tc.policyUnchanged && (policy.Name != before.Name || policy.Match != before.Match) {
					t.Fatalf("hook %d after the change: profile %+v; want %+v unchanged", i, policy, before)
				}
			}
			if !tc.recovers {
				return
			}
			time.Sleep(time.Millisecond)
			record := verified
			record.UpdatedAt = time.Now().UTC()
			writeRecord(record)
			if row, policy := hook("verified-again"); row["upn"] != upn || policy.Name != before.Name {
				t.Fatalf("verified again: row %v, profile %+v; want upn %s and %s", row, policy, upn, before.Name)
			}
		})
	}
}
