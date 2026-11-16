// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// RVI1-1 (pod identity workflow iteration 1 review, 37211b80ec): a local
// account behind SSSD in the passwd line (RHEL "sss files systemd") gets its
// account incarnation from the guardian's record, and the hook path asks
// for it at every recheck (every second). The guardian's answer is asked
// only after the gateway's own lookup did not name the incarnation, so the
// gateway's own lookup runs once per answer, not twice.
func TestGuardianIncarnationDoesNotRepeatTheGatewaysOwnLookup(t *testing.T) {
	const uid = 41470
	key := strconv.Itoa(uid)
	dir := t.TempDir()
	data, err := enterprisehooks.MarshalIdentitySpoolRecord(enterprisehooks.IdentitySpoolRecord{
		Key: key, User: "lali", UpdatedAt: time.Now().UTC(), AccountIncarnation: "files",
		Facts: useridentity.DirectoryFacts{Source: useridentity.SourceNSSFiles},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, key+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	previousValidate, previousDir := validateManagedGuardianAuthorization, currentIdentitySpoolDir()
	previousOwn, previousRecorded := managedHookPeerAccountIncarnation, managedHookPeerRecordedAccountIncarnation
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	setIdentitySpoolDir(dir)
	t.Cleanup(func() {
		validateManagedGuardianAuthorization = previousValidate
		managedHookPeerAccountIncarnation, managedHookPeerRecordedAccountIncarnation = previousOwn, previousRecorded
		setIdentitySpoolDir(previousDir)
	})
	var own, recorded atomic.Int32
	managedHookPeerAccountIncarnation = func(unixidentity.Account) (string, bool) { own.Add(1); return "", false }
	managedHookPeerRecordedAccountIncarnation = func(unixidentity.Account) (string, bool) { recorded.Add(1); return "files", true }
	account := unixidentity.Account{Name: "lali", UID: uid, Home: "/home/lali"}
	incarnation, known := peerAccountIncarnation(account)
	if !known || incarnation != "files" {
		t.Fatalf("local account behind SSSD: incarnation %q known %v; want the guardian record's files", incarnation, known)
	}
	if got := own.Load(); got != 1 {
		t.Fatalf("the gateway's own incarnation lookup ran %d times for one answer; want 1 (RVI1-1)", got)
	}
	if got := recorded.Load(); got != 1 {
		t.Fatalf("the recorded incarnation lookup ran %d times; want 1", got)
	}
}

// RVI1-3: holderNow, the hook path's at-once check of the uid's holder,
// names the incarnation as recheckAccount does: for a local account the
// gateway names only through the guardian's record, it reset the entry to
// "unknown" until the next recheck, and confirmCachedSpelling refused to
// confirm the account's cached facts in that window.
func TestHolderNowNamesTheIncarnationTheGuardianRecordProves(t *testing.T) {
	f := userdbAccountFixture(t)
	f.guardian("proof-1")
	account, incarnation, ok, known := managedHookPeerHomes.holderNow(f.uid)
	if !ok || account.Name != "alice" {
		t.Fatalf("holderNow(%d): account %+v ok %v", f.uid, account, ok)
	}
	if !known || incarnation != "nss:systemd" {
		t.Fatalf("holderNow(%d): incarnation %q known %v; want the guardian-proven nss:systemd (RVI1-3)", f.uid, incarnation, known)
	}
}
