// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func gap1800TrustAll(t *testing.T) {
	t.Helper()
	previousFile, previousDir := enterpriseHookAuthorizationFileTrustCheck, enterpriseHookAuthorizationDirTrustCheck
	t.Cleanup(func() {
		enterpriseHookAuthorizationFileTrustCheck, enterpriseHookAuthorizationDirTrustCheck = previousFile, previousDir
	})
	enterpriseHookAuthorizationFileTrustCheck = func(string) error { return nil }
	enterpriseHookAuthorizationDirTrustCheck = func(string) error { return nil }
}

// GAP-1800 (RV-1733c P4): with no ledger, activation record or guardian state
// (the first-adoption branch), an enrolled-accounts record that cannot be
// read was dropped: the branch overwrote "every" and lost recordErr, so the
// unreadable record read as an empty set and every account as never
// protected. An unreadable record counts every account as enrolled there
// too, as the record's own rule says.
func TestGAP1800UnreadableEnrolledAccountsRecordFailsClosedWithoutALedger(t *testing.T) {
	gap1800TrustAll(t)
	dataDir := t.TempDir()
	authorizationDir := managed.HookGuardianAuthorizationDir(dataDir)
	if err := os.MkdirAll(authorizationDir, 0o700); err != nil {
		t.Fatal(err)
	}
	enrolled := enterpriseHookEnrolledAccounts(dataDir, authorizationDir)
	if enrolled("S-1-5-21-1-2-3-1001") {
		t.Fatal("precondition: a host with none of the records is the first adoption, no account enrolled")
	}
	record := filepath.Join(authorizationDir, managed.HookGuardianEnrolledAccountsFile)
	if err := os.WriteFile(record, []byte("{\"version\":"), 0o600); err != nil {
		t.Fatal(err)
	}
	enrolled = enterpriseHookEnrolledAccounts(dataDir, authorizationDir)
	if !enrolled("S-1-5-21-1-2-3-1001") {
		t.Fatal("an unreadable enrolled-accounts record without a ledger read as no account enrolled (fail open)")
	}
}

// GAP-1800 (RV-1733c P4): the record key is the SID in the canonical form
// ConvertSidToStringSid renders (an uppercase S, decimal numbers without
// leading zeros, an identifier authority of 2^32 or more in hex), so two
// spellings of one SID name one account. A value that is not a SID keeps the
// earlier upper-case key.
func TestGAP1800EnrolledAccountKeyIsTheCanonicalSID(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1001"},
		{" s-1-5-21-1-2-3-1001 ", "S-1-5-21-1-2-3-1001"},
		{"S-1-5-21-0100-02-3-01001", "S-1-5-21-100-2-3-1001"},
		{"S-1-0x5-21-1-2-3-1001", "S-1-5-21-1-2-3-1001"},
		{"S-1-12-1-2154551306-1088420934-3105472945-2453215047", "S-1-12-1-2154551306-1088420934-3105472945-2453215047"},
		{"S-1-0x100000000-7", "S-1-0x000100000000-7"},
		{"uid:1001", "UID:1001"},
		{"S-1-5-21-1-2-3-99999999999", "S-1-5-21-1-2-3-99999999999"},
		{"", ""},
	} {
		if got := enterpriseHookEnrolledAccountKey(tc.in); got != tc.want {
			t.Errorf("enterpriseHookEnrolledAccountKey(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if enterpriseHookEnrolledAccountKey("S-1-5-21-1-2-3-01001") != enterpriseHookEnrolledAccountKey("s-1-5-21-1-2-3-1001") {
		t.Fatal("two spellings of one SID are two accounts")
	}
}
