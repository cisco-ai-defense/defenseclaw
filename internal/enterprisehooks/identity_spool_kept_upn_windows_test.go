// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

func writeKeptUPNTestRecord(t *testing.T, dir string, record IdentitySpoolRecord) {
	t.Helper()
	data, err := MarshalIdentitySpoolRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, record.Key+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// W19 review (loop round 1): a guardian pass keeps the last known UPN as
// GAP-0284 and GAP-0129 do, and marks a UPN it did not verify this pass.
func TestWindowsIdentitySpoolMarksAKeptUPN(t *testing.T) {
	for _, tc := range []struct {
		name, current string
		cacheKept     bool
		wantUPN       string
		wantKept      bool
	}{
		{"translation verified", "alice@corp.example", false, "alice@corp.example", false},
		{"translation verified a rename", "renamed@corp.example", false, "renamed@corp.example", false},
		{"translation unavailable", "", false, "alice@corp.example", true},
		{"the cache gave its last good answer", "alice@corp.example", true, "alice@corp.example", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeKeptUPNTestRecord(t, dir, IdentitySpoolRecord{Key: testSpoolUserA, User: `CORP\alice`,
				UpdatedAt: time.Now().UTC().Add(-time.Minute), UPNSource: UPNSourceTranslateName,
				Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory,
					UPN: "alice@corp.example", Principal: "alice@corp.example"}})
			stubWindowsIdentityLookups(t, nil, nil)
			windowsIdentityDirectoryFacts = func(string, time.Duration) useridentity.DirectoryFacts {
				return useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory,
					UPN: tc.current, UPNKept: tc.cacheKept, Principal: tc.current, Source: useridentity.SourceWindowsLSA}
			}
			cache := NewWindowsEnrollmentGroupCache()
			cache.Users[testSpoolUserA] = nil
			if err := WriteWindowsIdentitySpool(context.Background(), dir, cache, nil, nil, nil, nil); err != nil {
				t.Fatal(err)
			}
			got, err := ReadIdentitySpoolRecord(dir, testSpoolUserA, nil)
			if err != nil || got.Facts.UPN != tc.wantUPN || got.Facts.Principal != tc.wantUPN ||
				got.UPNSource != UPNSourceTranslateName || got.UPNKept() != tc.wantKept {
				t.Fatalf("record = %+v (%v), kept %t; want UPN and principal %q from translate_name, kept %t",
					got, err, got.UPNKept(), tc.wantUPN, tc.wantKept)
			}
		})
	}
}

// A token-group-only pass publishes the previous record's UPN with this
// pass's groups (loop round 3), and marks that UPN kept.
func TestWindowsIdentitySpoolMarksTheUPNOfATokenGroupRecordKept(t *testing.T) {
	const weak, strict = "S-1-5-21-111111111-222222222-333333333-7001", "S-1-5-21-111111111-222222222-333333333-7000"
	dir := t.TempDir()
	previousAt := time.Now().UTC().Add(-20 * time.Minute)
	writeKeptUPNTestRecord(t, dir, IdentitySpoolRecord{Key: testSpoolUserA, User: `CORP\user`, UpdatedAt: previousAt,
		UPNSource: UPNSourceTranslateName, Facts: useridentity.DirectoryFacts{UPN: "user@corp.example", Groups: []string{weak, `CORP\weak`}}})
	cache := NewWindowsEnrollmentGroupCache()
	cache.Users[testSpoolUserA] = []string{weak, strict}
	cache.SignedIn = map[string]bool{testSpoolUserA: true}
	previousWait := windowsIdentityAccountWait
	t.Cleanup(func() { windowsIdentityAccountWait = previousWait })
	windowsIdentityAccountWait = 50 * time.Millisecond
	release := make(chan struct{})
	stubWindowsIdentityLookups(t, func(string) { <-release }, nil)
	t.Cleanup(func() { close(release) })
	if err := WriteWindowsIdentitySpool(context.Background(), dir, cache, nil, nil, nil, nil); err == nil {
		t.Fatal("the late lookup was not reported")
	}
	record, err := ReadIdentitySpoolRecord(dir, testSpoolUserA, nil)
	if err != nil || !slices.Contains(record.Facts.Groups, strict) || record.Facts.UPN != "user@corp.example" ||
		record.UPNSource != UPNSourceTranslateName || !record.UPNKept() || !record.UPNKeptSince.Equal(record.UpdatedAt) {
		t.Fatalf("record = %+v (%v), kept %t; want the strict group and the previous UPN marked kept", record, err, record.UPNKept())
	}
}
