// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package gateway

import (
	"os"
	osuser "os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// TestResolvePeerDirectoryFactsWithoutSpool pins the per-user macOS path: with
// no guardian identity spool record the account's groups still resolve, so a
// users or groups assignment is not reported as default_lookup_failed.
func TestResolvePeerDirectoryFactsWithoutSpool(t *testing.T) {
	setIdentitySpoolDir("")
	current, err := osuser.Current()
	if err != nil {
		t.Skipf("current user: %v", err)
	}
	facts, err := resolvePeerDirectoryFacts(current.Uid)
	if err != nil || facts.ResolvedAt.IsZero() || len(facts.Groups) == 0 {
		t.Fatalf("facts = %+v, err = %v; want resolved groups", facts, err)
	}
}

// TestResolvePeerDirectoryFactsKeepsGroupsUnderSpool pins the managed macOS
// path: the enumerator's record has no groups, and the account's own groups
// must survive under its directory facts or no groups assignment can match
// (GAP-0123).
func TestResolvePeerDirectoryFactsKeepsGroupsUnderSpool(t *testing.T) {
	current, err := osuser.Current()
	if err != nil {
		t.Skipf("current user: %v", err)
	}
	dir := t.TempDir()
	data, err := enterprisehooks.MarshalIdentitySpoolRecord(enterprisehooks.IdentitySpoolRecord{
		Key: current.Uid, User: current.Username, UpdatedAt: time.Now().UTC(),
		Facts: useridentity.DirectoryFacts{
			Principal: "alice@CORP.EXAMPLE.COM", Directory: useridentity.DirectoryActiveDirectory,
			ResolvedAt: time.Now().UTC(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, current.Uid+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	restoreValidate := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = restoreValidate; setIdentitySpoolDir("") })
	setIdentitySpoolDir(dir)
	facts, err := resolvePeerDirectoryFacts(current.Uid)
	if err != nil || len(facts.Groups) == 0 || facts.Directory != useridentity.DirectoryActiveDirectory ||
		facts.Principal != "alice@corp.example.com" || facts.Assurance != useridentity.AssuranceVerified {
		t.Fatalf("facts = %+v, err = %v; want the account groups under the record's directory facts", facts, err)
	}
}
