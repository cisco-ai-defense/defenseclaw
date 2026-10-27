// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

func writeIdentityCallerRecord(t *testing.T, dir string, record enterprisehooks.IdentitySpoolRecord) {
	t.Helper()
	record.Version = enterprisehooks.IdentitySpoolRecordVersion
	record.UpdatedAt = time.Now().UTC()
	data, err := enterprisehooks.MarshalIdentitySpoolRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, record.Key+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// GAP-0937: exempt_users: [alice] exempts the local alice by her name and the
// directory account alice@corp.example.com by its facts
// (managedHookAuthorizer.exempt). The account database resolves alice to the
// local account, and the records were read only when the lookup failed, so
// the directory account's record, which nothing else lists, aged out while
// the gateway still exempted it. Both stay listed now. A record of a uid
// that another account holds now still lists nothing.
func TestExemptNameKeepsTheRecordOfADirectoryNamesake(t *testing.T) {
	identityCallerTestConfig(t)
	const localUID, directoryUID, reusedUID = 94409371, 94409372, 94409373
	enterprisehooks.SetStandaloneResolver(standaloneTestResolver{accounts: map[string]unixidentity.Account{
		"alice":                  {Name: "alice", UID: localUID, GID: localUID},
		"alice@corp.example.com": {Name: "alice@corp.example.com", UID: directoryUID, GID: directoryUID},
		"mallory":                {Name: "mallory", UID: reusedUID, GID: reusedUID},
	}})
	cfg.Enterprise.Enrollment.ExemptUsers = []string{"alice"}
	dir := t.TempDir()
	writeIdentityCallerRecord(t, dir, enterprisehooks.IdentitySpoolRecord{Key: strconv.Itoa(localUID), User: "alice", AccountIncarnation: "files"})
	directory := enterprisehooks.IdentitySpoolRecord{Key: strconv.Itoa(directoryUID), User: "alice@corp.example.com",
		AccountIncarnation: "sid:S-1-5-21-1-2-3-1372", SSSDDomain: "corp.example.com",
		Facts: useridentity.DirectoryFacts{UPN: "alice.smith@corp.example.com", Domain: "corp.example.com"}}
	writeIdentityCallerRecord(t, dir, directory)
	reused := directory
	reused.Key, reused.AccountIncarnation = strconv.Itoa(reusedUID), "sid:S-1-5-21-1-2-3-1373"
	writeIdentityCallerRecord(t, dir, reused)
	accounts, _, _ := enterpriseHookIdentitySpoolAccounts(context.Background(), io.Discard, dir, enterpriseHookReconcileRun{})
	listed, _ := listedUIDs(accounts)
	if !slices.Contains(listed, localUID) || !slices.Contains(listed, directoryUID) {
		t.Fatalf("exempt_users [alice] with a local alice and a directory alice@corp.example.com: listed %v; want both", listed)
	}
	if slices.Contains(listed, reusedUID) {
		t.Fatalf("listed %v; uid %d is mallory's now, and the old record of it must not be refreshed", listed, reusedUID)
	}
}

// GAP-0964: the records an exempt name's spellings are matched against were
// read up to 4,096, so on a larger host an exempt caller whose record file
// sorted later was never matched while its UPN did not resolve, and its
// record aged out. Every record is read now.
func TestExemptNameFindsItsRecordPastTheFirst4096(t *testing.T) {
	identityCallerTestConfig(t)
	const uid = 94409640
	enterprisehooks.SetStandaloneResolver(standaloneTestResolver{accounts: map[string]unixidentity.Account{}})
	cfg.Enterprise.Enrollment.ExemptUsers = []string{"bob.smith@corp.example.com"}
	dir := t.TempDir()
	for i := range 4100 {
		key := strconv.Itoa(1_000_000 + i) // sorts before 94409640
		writeIdentityCallerRecord(t, dir, enterprisehooks.IdentitySpoolRecord{Key: key, User: "u" + key, AccountIncarnation: "files"})
	}
	writeIdentityCallerRecord(t, dir, enterprisehooks.IdentitySpoolRecord{Key: strconv.Itoa(uid), User: "bob",
		AccountDomain: "CORP", AccountIncarnation: "sid:S-1-5-21-1-2-3-1964", SSSDDomain: "corp.example.com",
		Facts: useridentity.DirectoryFacts{UPN: "bob.smith@corp.example.com", Domain: "corp.example.com"}})
	accounts, _, _ := enterpriseHookIdentitySpoolAccounts(context.Background(), io.Discard, dir, enterpriseHookReconcileRun{})
	if listed, _ := listedUIDs(accounts); !slices.Equal(listed, []int{uid}) {
		t.Fatalf("exempt UPN whose record is number 4,101: listed %d uids %v; want only %d", len(listed), listed[:min(len(listed), 5)], uid)
	}
}
