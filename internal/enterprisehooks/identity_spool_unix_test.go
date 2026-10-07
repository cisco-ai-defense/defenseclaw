// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// TestIdentitySpoolKeepsRecordsOfAccountsAPassDidNotList pins GAP-0145: a
// pass that did not list an account (it could not decide it while the
// directory was unreachable) must not delete its record while the gateway
// still trusts it; a record older than that goes.
func TestIdentitySpoolKeepsRecordsOfAccountsAPassDidNotList(t *testing.T) {
	dir := t.TempDir()
	for name, age := range map[string]time.Duration{"94401103.json": 5 * time.Minute, "94401104.json": 2 * IdentitySpoolMaxAge} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("{}"), 0o640); err != nil {
			t.Fatal(err)
		}
		when := time.Now().Add(-age)
		if err := os.Chtimes(path, when, when); err != nil {
			t.Fatal(err)
		}
	}
	if err := WriteIdentitySpool(context.Background(), dir, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "94401103.json")); err != nil {
		t.Errorf("the record of an unlisted account that is still trusted was removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "94401104.json")); !os.IsNotExist(err) {
		t.Errorf("a record older than IdentitySpoolMaxAge was kept (stat error %v)", err)
	}
}

// GAP-0284: a record that resolved no UPN (a signed-out Windows user) keeps
// the account's last known UPN and principal instead of account@REALM.
func TestIdentitySpoolKeepsTheLastKnownUPN(t *testing.T) {
	const sid = "S-1-5-21-1111-2222-3333-1105"
	previous := IdentitySpoolRecord{Key: sid, UPNSource: UPNSourceTranslateName, Facts: useridentity.DirectoryFacts{
		Principal: "dcad-alice@dclab.test", UPN: "dcad-alice@dclab.test", Domain: "dclab.test", Realm: "DCLAB.TEST",
	}}
	signedOut := IdentitySpoolRecord{Key: sid, Facts: useridentity.DirectoryFacts{
		Principal: useridentity.AccountPrincipal("dcad-alice", "DCLAB.TEST"), Realm: "DCLAB.TEST",
	}}
	got := KeepLastKnownUPN(signedOut, previous)
	if got.Facts.UPN != "dcad-alice@dclab.test" || got.Facts.Principal != "dcad-alice@dclab.test" ||
		got.UPNSource != UPNSourceTranslateName {
		t.Fatalf("record = %+v, want the last known UPN", got)
	}
	if other := KeepLastKnownUPN(IdentitySpoolRecord{Key: "S-1-5-21-1111-2222-3333-1106"}, previous); other.Facts.UPN != "" {
		t.Fatalf("another account took the UPN: %+v", other)
	}
}
