// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// GAP-1233: alice (uid 1001) was removed and the uid now belongs to bob. A
// removal record that still names alice must not carry bob's verified
// principal; a record that names bob, the uid's account now, still does.
func TestInventoryRecordOfAReusedUIDDoesNotTakeTheNewHoldersFacts(t *testing.T) {
	restoreFacts := identityFactsEnabled.Load()
	identityFactsEnabled.Store(true)
	originalDirectory, originalName := managedHookPeerDirectory, userScopedIdentityName
	managedHookPeerDirectory = func(uid int, _ bool) (useridentity.DirectoryFacts, bool) {
		if uid != 1001 {
			return useridentity.DirectoryFacts{}, false
		}
		return useridentity.DirectoryFacts{
			Principal: "bob@dclab.test", UPN: "bob@dclab.test", Domain: "dclab.test",
			Groups: []string{"dc-ml-team@dclab.test"}, Source: useridentity.SourceSSSDInfoPipe,
			Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now(),
		}, true
	}
	userScopedIdentityName = func(id string) string {
		if id == "1001" {
			return "bob"
		}
		return ""
	}
	t.Cleanup(func() {
		identityFactsEnabled.Store(restoreFacts)
		managedHookPeerDirectory, userScopedIdentityName = originalDirectory, originalName
	})

	if identity := inventoryIdentityFor("1001", "alice"); identity != nil {
		t.Fatalf("alice's record took the new holder's facts: %+v", identity.Directory)
	}
	if identity := inventoryIdentityFor("1001", "bob"); identity == nil || identity.Directory.Principal != "bob@dclab.test" {
		t.Fatalf("bob's record lost his own facts: %+v", identity)
	}
	// A record that names no account cannot show it is the uid's account now.
	if identity := inventoryIdentityFor("1001", ""); identity != nil {
		t.Fatalf("a record that names no account took the uid's facts: %+v", identity.Directory)
	}
	// The same bare name in another domain is another principal.
	userScopedIdentityName = func(id string) string {
		if id == "1001" {
			return "alice@new.example"
		}
		return ""
	}
	if identity := inventoryIdentityFor("1001", "alice@old.example"); identity != nil {
		t.Fatalf("alice@old.example's record took alice@new.example's facts: %+v", identity.Directory)
	}
	if identity := inventoryIdentityFor("1001", "ALICE@new.example"); identity == nil {
		t.Fatal("the uid's own qualified account, spelled in another case, lost its facts")
	}
}
