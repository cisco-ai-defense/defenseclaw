// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// rel-1-0-4 GAP-0596: an agent identity row names the UPN of a directory
// account, from the facts the hook path cached for its uid, as the Windows
// row does for a SID; a local account's row names none.
func TestAgentIdentitiesListTheUPNOfADirectoryAccount(t *testing.T) {
	agentIdentityTestSetup(t)
	const uid, local = 1_870_400_596, 1_870_400_597
	previous, previousFacts := managedHookPeerHomes, identityFactsEnabled.Load()
	managedHookPeerHomes = &managedHookPeerHomeCache{
		newResolver: func() unixidentity.Resolver {
			return &fakePeerHomeResolver{accounts: map[int]unixidentity.Account{
				uid:   {Name: "grace@corp.example.com", UID: uid, Home: "/home/grace"},
				local: {Name: "heidi", UID: local, Home: "/home/heidi"},
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
		managedHookPeerHomes.directories = newIdentityDirectoryCache(func(key string) (useridentity.DirectoryFacts, error) {
			if key == strconv.Itoa(local) {
				return useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal, ResolvedAt: time.Now()}, nil
			}
			return useridentity.DirectoryFacts{
				Directory: useridentity.DirectoryActiveDirectory, Domain: "corp.example.com", Realm: "CORP.EXAMPLE.COM",
				Principal: "grace@CORP.EXAMPLE.COM", UPN: "grace@corp.example.com", ResolvedAt: time.Now(),
			}, nil
		})
	})
	for _, id := range []int{uid, local} {
		if _, ok := managedHookPeerHomes.directory(id, true); !ok {
			t.Fatalf("the hook path did not cache the facts of %d", id)
		}
	}
	store, err := inventory.NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	prev := sharedAgentIdentities
	sharedAgentIdentities = &agentIdentityRecorder{pending: map[string]*inventory.AgentIdentityRecord{}, hints: map[string]string{}}
	sharedAgentIdentities.setStoreSource(func() *inventory.InventoryStore { return store }, nil, nil)
	t.Cleanup(func() { sharedAgentIdentities = prev })

	hook := agentHookRequest{ConnectorName: "codex", SessionID: "sess-upn", HookEventName: "PreToolUse", Payload: map[string]interface{}{}}
	grace := agentIdentityForGenericHook(withManagedHookPeer(context.Background(),
		managedHookPeer{UID: uid, Name: "grace@corp.example.com", Home: t.TempDir()}), hook)
	heidi := agentIdentityForGenericHook(withManagedHookPeer(context.Background(),
		managedHookPeer{UID: local, Name: "heidi", Home: t.TempDir()}), hook)
	rows := listedAgentIdentityRows(t)
	if row := rows[grace.IdentityID]; row == nil || row["upn"] != "grace@corp.example.com" {
		t.Fatalf("directory account row = %v, want upn grace@corp.example.com", row)
	}
	if row := rows[heidi.IdentityID]; row == nil {
		t.Fatalf("local account %s not listed in %v", heidi.IdentityID, rows)
	} else if _, named := row["upn"]; named {
		t.Fatalf("local account row = %v, want no upn", row)
	}
}
