// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"sync"
	"testing"
	"time"
)

// GAP-2108: a fresh local account's first Codex turn came before the
// guardian's next one-minute tick spooled its identity record, and the
// gateway refused it "group membership is unconfirmed". The watch loop
// follows the local account database's stamp, so a useradd or usermod
// triggers a reconcile within seconds; an unchanged stamp triggers nothing.
func TestAccountDatabaseChangesFollowTheLocalAccountsStamp(t *testing.T) {
	identityCallerTestConfig(t)
	previousStamp, previousPoll := enterpriseHookLocalAccountsStamp, enterpriseHookAccountDatabasePoll
	t.Cleanup(func() {
		enterpriseHookLocalAccountsStamp, enterpriseHookAccountDatabasePoll = previousStamp, previousPoll
	})
	var mu sync.Mutex
	stamp := "1/100/7"
	enterpriseHookLocalAccountsStamp = func() string { mu.Lock(); defer mu.Unlock(); return stamp }
	enterpriseHookAccountDatabasePoll = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes := enterpriseHookAccountDatabaseChanges(ctx)
	if changes == nil {
		t.Fatal("the standalone guardian follows no account database changes")
	}
	select {
	case <-changes:
		t.Fatal("a change was reported while the account database did not change")
	case <-time.After(50 * time.Millisecond):
	}
	mu.Lock()
	stamp = "2/120/7"
	mu.Unlock()
	select {
	case <-changes:
	case <-time.After(2 * time.Second):
		t.Fatal("a useradd (new stamp) triggered no reconcile")
	}
	select {
	case <-changes:
		t.Fatal("one account database change was reported twice")
	case <-time.After(50 * time.Millisecond):
	}

	// Off the standalone guardian, and where no stamp is kept (macOS),
	// nothing is followed.
	enterpriseHookLocalAccountsStamp = func() string { return "" }
	if enterpriseHookAccountDatabaseChanges(ctx) != nil {
		t.Fatal("followed an account database that keeps no stamp")
	}
	cfg = nil
	enterpriseHookLocalAccountsStamp = func() string { return "1/100/7" }
	if enterpriseHookAccountDatabaseChanges(ctx) != nil {
		t.Fatal("followed the account database outside the standalone guardian")
	}
}
