// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package procprobe

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// slowAccounts is an account database that answers only when released, like
// SSSD or Open Directory waiting on a domain controller.
type slowAccounts struct {
	directoryAccounts
	release chan struct{}
}

func (s *slowAccounts) LookupUID(uid int) (unixidentity.Account, error) {
	<-s.release
	return s.directoryAccounts.LookupUID(uid)
}

// p0-round GAP-1389 review: an event source names a process's account from
// its read loop. A lookup that waits on a directory service there stalls the
// reader and the kernel drops events, so the cached name never waits: it is
// empty until a background lookup answers, then the account's name.
func TestCachedOwnerNameNeverWaitsOnTheAccountDatabase(t *testing.T) {
	const uid = 94404120
	slow := &slowAccounts{release: make(chan struct{}),
		directoryAccounts: directoryAccounts{accounts: map[int]unixidentity.Account{uid: {Name: "eng2@corp.example", UID: uid}}}}
	useDirectoryAccounts(t, &slow.directoryAccounts)
	previous := ownerAccounts
	ownerAccounts = func(context.Context) unixidentity.Resolver { return slow }
	t.Cleanup(func() { ownerAccounts = previous })

	start := time.Now()
	if got := CachedOwnerName(uid); got != "" {
		t.Fatalf("first CachedOwnerName = %q, want none before the lookup answered", got)
	}
	if got := CachedOwnerName(uid); got != "" {
		t.Fatalf("second CachedOwnerName = %q, want none while the lookup runs", got)
	}
	if waited := time.Since(start); waited > 500*time.Millisecond {
		t.Fatalf("CachedOwnerName waited %s for the account database", waited)
	}
	close(slow.release)
	deadline := time.Now().Add(5 * time.Second)
	for CachedOwnerName(uid) != "eng2@corp.example" {
		if time.Now().After(deadline) {
			t.Fatal("the background lookup never named the account")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for {
		if _, busy := ownerFills.Load(uid); !busy {
			break
		}
		time.Sleep(time.Millisecond)
	}
}
