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

// rel-1-0-6 GAP-0789: the enumerator publishes the same unprotected agents
// it writes to the root-only record for the gateway, which answers a user's
// own status from them; an empty scan withdraws the copy.
func TestGatewayUnprotectedAgentsCopyFollowsTheScan(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, dir)
	oldOwner, oldTrust, oldDirTrust := enterpriseHookAuthorizationOwnershipSetter, enterpriseHookAuthorizationFileTrustCheck, enterpriseHookAuthorizationDirTrustCheck
	t.Cleanup(func() {
		enterpriseHookAuthorizationOwnershipSetter, enterpriseHookAuthorizationFileTrustCheck, enterpriseHookAuthorizationDirTrustCheck = oldOwner, oldTrust, oldDirTrust
	})
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	enterpriseHookAuthorizationFileTrustCheck = func(string) error { return nil }
	enterpriseHookAuthorizationDirTrustCheck = func(string) error { return nil }

	uid := 1006
	agents := []enterprisehooks.UnprotectedAgent{{
		User: "r109ye1", UID: &uid, Connector: "opencode", Version: "1.18.34",
		InstallPath: "/opt/dc-agents/lib/node_modules/opencode-ai",
		Code:        enterprisehooks.UnprotectedCodeOpenCodeV1, Reason: "V1 copy",
	}}
	if err := writeEnterpriseHookGatewayUnprotectedAgents(dir, agents); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, managed.HookGuardianUnprotectedAgentsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := enterprisehooks.ParseUnprotectedAgents(data)
	if err != nil || len(got) != 1 || got[0].User != "r109ye1" || got[0].Connector != "opencode" ||
		got[0].Code != enterprisehooks.UnprotectedCodeOpenCodeV1 || got[0].UID == nil || *got[0].UID != uid {
		t.Fatalf("published copy = %+v, %v; want the scan's OpenCode V1 entry", got, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("copy mode = %v, %v; want 0640 like the ledger", info, err)
	}
	if err := writeEnterpriseHookGatewayUnprotectedAgents(dir, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an empty scan left the copy in place: %v", err)
	}
}
