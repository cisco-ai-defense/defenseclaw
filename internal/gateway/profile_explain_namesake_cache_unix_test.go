//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

func TestProfileExplainCachedNamesBindToUID(t *testing.T) {
	previous, enabled := managedHookPeerHomes, identityFactsEnabled.Load()
	resolver := &changingHolderAccounts{accounts: map[int]unixidentity.Account{
		2100:  {UID: 2100, Name: "alex", Home: "/home/local"},
		80001: {UID: 80001, Name: "alex", Home: "/home/directory"},
	}}
	managedHookPeerHomes = holderTestCache(t, resolver, useridentity.DirectoryLocal, time.Now)
	setIdentityFactsEnabled(true)
	t.Cleanup(func() { managedHookPeerHomes = previous; setIdentityFactsEnabled(enabled) })
	for _, uid := range []int{2100, 80001} {
		if _, err := managedHookPeerHomes.explainDirectory(uid); err != nil {
			t.Fatal(err)
		}
	}
	if uid, _, ok := managedHookPeerHomes.cachedHolder("alex"); ok {
		t.Fatalf("ambiguous cached account name selected uid %d", uid)
	}
	if uid, name, ok := managedHookPeerHomes.cachedHolder("2100"); !ok || uid != 2100 || name != "alex" {
		t.Fatalf("explicit uid selected %d, %q, %t", uid, name, ok)
	}
	local := unixidentity.Account{Name: "alex", UID: 2100}
	twins, _ := sameNameProfileAccounts(context.Background(), nil, "alex", local)
	if len(twins) != 1 || twins[0].UID != 80001 {
		t.Fatalf("cached accounts sharing a bare name = %+v", twins)
	}
}
