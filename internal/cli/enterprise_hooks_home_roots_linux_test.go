// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// GAP-2028: an SSSD or LDAP account without a SID deleted and created again
// under the same name, uid and home path changes no account database file,
// so the guardian rewrote its record (and the gateway kept taking the earlier
// holder's home proof) only at its next tick, and not at all while the new
// home got the old inode number. Removing and creating the home changes the
// directory that holds it: the watch loop reconciles within seconds, and the
// identity spool's fingerprint changes so the pass rewrites the record.
func TestARecreatedHomeTriggersAReconcileAndAnIdentitySpoolPass(t *testing.T) {
	identityCallerTestConfig(t)
	previousStamp, previousPoll, previousRoots := enterpriseHookLocalAccountsStamp, enterpriseHookAccountDatabasePoll, enterpriseHookHomeRoots.Load()
	t.Cleanup(func() {
		enterpriseHookLocalAccountsStamp, enterpriseHookAccountDatabasePoll = previousStamp, previousPoll
		enterpriseHookHomeRoots.Store(previousRoots)
	})
	enterpriseHookLocalAccountsStamp = func() string { return "1/100/7" }
	enterpriseHookAccountDatabasePoll = 5 * time.Millisecond
	homes := filepath.Join(t.TempDir(), "home")
	home := filepath.Join(homes, "ldapu")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	enterpriseHookNoteHomeRoots([]enterpriseHookReconcileRow{{User: "ldapu", UID: 52601, UserHome: home}})
	keys := []string{"52601:ldapu:7"}
	before := enterpriseHookIdentitySpoolFingerprint(keys)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes := enterpriseHookAccountDatabaseChanges(ctx)
	if changes == nil {
		t.Fatal("the standalone guardian follows no account changes")
	}
	select {
	case <-changes:
		t.Fatal("a change was reported while no home changed")
	case <-time.After(50 * time.Millisecond):
	}
	if err := os.Remove(home); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(home, 0o755); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changes:
	case <-time.After(2 * time.Second):
		t.Fatal("a home removed and created again triggered no reconcile")
	}
	if after := enterpriseHookIdentitySpoolFingerprint(keys); after == before {
		t.Fatalf("the identity spool fingerprint %q did not change with a recreated home under the same keys", before)
	}
}
