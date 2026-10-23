// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// A Windows guardian pass can change or remove a UPN without changing token
// groups. The next hook must use the new record, including an empty UPN.
func TestWindowsSpoolUPNChangeInvalidatesCachedIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, current string
		directory     useridentity.Directory
	}{
		{"UPN changed", "renamed@corp.example", useridentity.DirectoryActiveDirectory},
		{"UPN casing changed", "Alice@corp.example", useridentity.DirectoryActiveDirectory},
		{"UPN removed", "", useridentity.DirectoryActiveDirectory},
		{"token-only pass has no UPN", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const sid = "S-1-5-21-1-2-3-1105"
			dir := t.TempDir()
			previousDir, previousValidate := currentIdentitySpoolDir(), validateManagedGuardianAuthorization
			setIdentitySpoolDir(dir)
			validateManagedGuardianAuthorization = func(string, string) error { return nil }
			t.Cleanup(func() {
				setIdentitySpoolDir(previousDir)
				validateManagedGuardianAuthorization = previousValidate
			})
			write := func(upn string, directory useridentity.Directory, at time.Time) {
				t.Helper()
				data, err := enterprisehooks.MarshalIdentitySpoolRecord(enterprisehooks.IdentitySpoolRecord{
					Key: sid, UpdatedAt: at, Facts: useridentity.DirectoryFacts{
						Directory: directory, UPN: upn,
						Groups: []string{"S-1-5-21-1-2-3-513"},
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, sid+".json"), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			lookupAt := time.Now().UTC()
			write("alice@corp.example", useridentity.DirectoryActiveDirectory, lookupAt.Add(-2*time.Minute))
			cache := newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
				record, ok := readIdentitySpoolFacts(sid, time.Now())
				if !ok {
					return useridentity.DirectoryFacts{}, errors.New("no current guardian record")
				}
				facts := record.Facts
				// The guardian stamps its new record before its lookup finishes.
				// The gateway can cache the old record after that timestamp.
				facts.ResolvedAt = lookupAt
				return facts, nil
			})
			if first, ok := cache.get(sid, true); !ok || first.UPN != "alice@corp.example" {
				t.Fatalf("first facts = %+v, ok %t", first, ok)
			}
			write(tc.current, tc.directory, lookupAt.Add(-30*time.Second))
			forgetOnSpoolGroupChange(cache, sid, time.Now())
			if current, ok := cache.get(sid, true); !ok || current.UPN != tc.current {
				t.Fatalf("current facts = %+v, ok %t; want UPN %q", current, ok, tc.current)
			}
		})
	}
}

func TestMergeSpoolFactsUsesCurrentWindowsADUPN(t *testing.T) {
	for _, tc := range []struct {
		name, current string
		directory     useridentity.Directory
	}{
		{"UPN changed", "renamed@corp.example", useridentity.DirectoryActiveDirectory},
		{"UPN removed", "", useridentity.DirectoryActiveDirectory},
		{"token-only pass has no UPN", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			own := useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory,
				UPN: "alice@corp.example", Principal: "alice@corp.example", Source: useridentity.SourceWindowsIdentityStore}
			record := enterprisehooks.IdentitySpoolRecord{Key: "S-1-5-21-1-2-3-1105",
				Facts: useridentity.DirectoryFacts{Directory: tc.directory,
					UPN: tc.current, Principal: tc.current, Source: useridentity.SourceWindowsLSA}}
			merged := mergeSpoolFacts(own, record)
			if merged.UPN != tc.current || merged.Source != useridentity.SourceWindowsLSA {
				t.Fatalf("merged UPN = %q, source = %q; want current %q from Windows LSA", merged.UPN, merged.Source, tc.current)
			}
		})
	}
}
