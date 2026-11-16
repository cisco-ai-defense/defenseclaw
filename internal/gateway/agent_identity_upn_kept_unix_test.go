// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// W19 review (loop round 1): a UPN the guardian kept (InfoPipe's
// infopipe_kept) still selects profiles, but an agent identity row lists
// only a UPN the latest guardian pass verified.
func TestAgentIdentityUPNOmitsAKeptGuardianUPN(t *testing.T) {
	agentIdentityTestSetup(t)
	const kept, verified = 1_870_400_610, 1_870_400_611
	previous, previousFacts := managedHookPeerHomes, identityFactsEnabled.Load()
	managedHookPeerHomes = &managedHookPeerHomeCache{
		newResolver: func() unixidentity.Resolver {
			return &fakePeerHomeResolver{accounts: map[int]unixidentity.Account{
				kept:     {Name: "kate", UID: kept, Home: "/home/kate"},
				verified: {Name: "liam", UID: verified, Home: "/home/liam"},
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
			own := useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory, Domain: "corp.example.com",
				Realm: "CORP.EXAMPLE.COM", ResolvedAt: time.Now()}
			record := enterprisehooks.IdentitySpoolRecord{Key: key, UPNSource: enterprisehooks.UPNSourceInfoPipe,
				Facts: useridentity.DirectoryFacts{UPN: key + "@corp.example.com", Principal: key + "@corp.example.com"}}
			if key == strconv.Itoa(kept) {
				record.UPNSource, record.UPNKeptSince = enterprisehooks.UPNSourceInfoPipeKept, time.Now().Add(-time.Hour)
			}
			return mergeSpoolFacts(own, record), nil
		})
	})
	for _, id := range []int{kept, verified} {
		facts, ok := managedHookPeerHomes.directory(id, true)
		if !ok || facts.UPN != strconv.Itoa(id)+"@corp.example.com" {
			t.Fatalf("policy facts of %d = %+v, %t; want the guardian's UPN", id, facts, ok)
		}
	}
	if upn, known := agentIdentityAccountUPN(strconv.Itoa(kept)); upn != "" || known {
		t.Fatalf("kept UPN row = %q, known %t; want no current UPN", upn, known)
	}
	if upn, known := agentIdentityAccountUPN(strconv.Itoa(verified)); upn != strconv.Itoa(verified)+"@corp.example.com" || !known {
		t.Fatalf("verified UPN row = %q, known %t", upn, known)
	}
}
