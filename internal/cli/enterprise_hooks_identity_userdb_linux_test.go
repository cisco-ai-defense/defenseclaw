// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// GAP-0026: on a machine-policy host with profile_assignments, a fresh
// systemd-userdb account (a drop-in record, no /etc/passwd line) is warmed
// up as a fresh /etc/passwd account is (GAP-0677): the guardian's identity
// spool pass lists it, so the gateway holds its record before its first
// Codex turn instead of refusing "the account holder is unconfirmed".
func TestMachinePolicyWarmsAFreshUserdbAccountsIdentity(t *testing.T) {
	identityCallerTestConfig(t)
	cfg.Enterprise.Enrollment.UnenrolledUsers = config.EnterpriseUnenrolledInspect
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: "relaxed", Match: config.ProfileMatch{Users: []string{"someone@corp.example"}}}}
	previousMachine, previousUserdb := enterpriseHookLoadMachinePolicyConnectors, unixidentity.UserdbRecordDirs
	t.Cleanup(func() {
		enterpriseHookLoadMachinePolicyConnectors = previousMachine
		unixidentity.UserdbRecordDirs = previousUserdb
	})
	enterpriseHookLoadMachinePolicyConnectors = func() ([]string, error) { return []string{"codex"}, nil }
	userdb := t.TempDir()
	unixidentity.UserdbRecordDirs = []string{userdb}
	record := `{"userName":"podudb","uid":28611,"gid":100,"homeDirectory":"/home/podudb","disposition":"regular"}`
	if err := os.WriteFile(filepath.Join(userdb, "podudb.user"), []byte(record), 0o644); err != nil {
		t.Fatal(err)
	}
	enterprisehooks.SetStandaloneResolver(standaloneTestResolver{accounts: map[string]unixidentity.Account{
		"podudb": {Name: "podudb", UID: 28611, GID: 100},
	}})
	accounts, keys, _ := enterpriseHookIdentitySpoolAccounts(context.Background(), io.Discard, t.TempDir(), enterpriseHookReconcileRun{})
	listed, _ := listedUIDs(accounts)
	if !slices.Contains(listed, 28611) || !slices.Contains(keys, "28611:podudb") {
		t.Fatalf("fresh userdb account not warmed up: accounts %+v keys %v", accounts, keys)
	}
	for _, account := range accounts {
		if account.UID == 28611 && (!account.Peer || account.PreTokenHolder) {
			t.Fatalf("warm-up account %+v writes the first migration map", account)
		}
	}
}
