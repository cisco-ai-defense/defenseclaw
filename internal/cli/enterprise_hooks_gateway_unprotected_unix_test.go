//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func gatewayCopyFixture(t *testing.T) (dir, path string) {
	t.Helper()
	dir = t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, dir)
	oldOwner, oldTrust, oldDirTrust := enterpriseHookAuthorizationOwnershipSetter, enterpriseHookAuthorizationFileTrustCheck, enterpriseHookAuthorizationDirTrustCheck
	t.Cleanup(func() {
		enterpriseHookAuthorizationOwnershipSetter, enterpriseHookAuthorizationFileTrustCheck, enterpriseHookAuthorizationDirTrustCheck = oldOwner, oldTrust, oldDirTrust
	})
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	enterpriseHookAuthorizationFileTrustCheck = func(string) error { return nil }
	enterpriseHookAuthorizationDirTrustCheck = func(string) error { return nil }
	return dir, filepath.Join(dir, managed.HookGuardianUnprotectedAgentsFile)
}

// rel-1-0-6 GAP-0789: the enumerator publishes its completed scan for the
// gateway, which answers a user own status from it. The copy is the same
// record the root-only file holds (agents, install generation, config stamp),
// and a scan that found nothing is published too: an absent copy is an
// unknown scan to the gateway, never "nothing found".
func TestGatewayUnprotectedAgentsCopyIsTheCompletedScan(t *testing.T) {
	dir, path := gatewayCopyFixture(t)
	uid := 1006
	agents := []enterprisehooks.UnprotectedAgent{{
		User: "r109ye1", UID: &uid, Connector: "opencode", Version: "1.18.34",
		InstallPath: "/opt/dc-agents/lib/node_modules/opencode-ai",
		Code:        enterprisehooks.UnprotectedCodeOpenCodeV1, Reason: "V1 copy",
	}}
	if err := publishEnterpriseHookGatewayUnprotectedAgents(dir, agents, 7, "digest-7"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := enterprisehooks.ParseUnprotectedAgents(data)
	if err != nil || len(got) != 1 || got[0].User != "r109ye1" || got[0].Connector != "opencode" ||
		got[0].Code != enterprisehooks.UnprotectedCodeOpenCodeV1 || got[0].UID == nil || *got[0].UID != uid {
		t.Fatalf("published copy = %+v, %v; want the scan OpenCode V1 entry", got, err)
	}
	if enterprisehooks.UnprotectedAgentsRecordConfigGeneration(data) != 7 || enterprisehooks.UnprotectedAgentsRecordConfigSHA256(data) != "digest-7" ||
		enterprisehooks.UnprotectedAgentsRecordGeneration(data) != enterprisehooks.UnprotectedAgentsGeneration() {
		t.Fatalf("copy is not stamped with the install generation and config stamp: %s", data)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("copy mode = %v, %v; want 0640 like the ledger", info, err)
	}
	// A scan that found nothing leaves a record, not an absent file.
	if err := publishEnterpriseHookGatewayUnprotectedAgents(dir, nil, 7, "digest-7"); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("an empty scan left no copy: %v", err)
	}
	if got, err := enterprisehooks.ParseUnprotectedAgents(data); err != nil || len(got) != 0 {
		t.Fatalf("empty scan copy = %+v, %v; want a record with no agents", got, err)
	}
}

// When the copy cannot be written the previous one is withdrawn: it must not
// speak for a scan this cycle replaced.
func TestGatewayUnprotectedAgentsCopyIsWithdrawnWhenItCannotBeWritten(t *testing.T) {
	dir, path := gatewayCopyFixture(t)
	if err := publishEnterpriseHookGatewayUnprotectedAgents(dir, nil, 7, "digest-7"); err != nil {
		t.Fatal(err)
	}
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return errors.New("cannot set the owner") }
	uid := 1006
	v1 := []enterprisehooks.UnprotectedAgent{{User: "r109ye1", UID: &uid, Connector: "opencode", Code: enterprisehooks.UnprotectedCodeOpenCodeV1, Reason: "V1 copy"}}
	if err := publishEnterpriseHookGatewayUnprotectedAgents(dir, v1, 7, "digest-7"); err == nil {
		t.Fatal("publishing with a failing ownership step reported success")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the previous copy still stands after a failed publication: %v", err)
	}
}
