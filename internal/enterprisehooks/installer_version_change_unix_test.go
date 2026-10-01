//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// TestStandaloneRepairFollowsAnEnrolledUsersAgentUpgrade walks the guardian's
// verify-or-repair pass after the enumerator recorded a Codex upgrade that
// changes the hook contract: verify reports the stale lock, the repair
// re-renders the hooks and writes a lock for the new contract, and verify
// then passes. Outside the standalone profile the same repair is refused.
func TestStandaloneRepairFollowsAnEnrolledUsersAgentUpgrade(t *testing.T) {
	skipIfRoot(t)
	t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "")
	home := newTestHome(t)
	codexConfig := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(codexConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(codexConfig, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	options := func(version string) InstallOptions {
		return InstallOptions{
			ConnectorName: "codex",
			UserHome:      home,
			OwnerUID:      os.Getuid(),
			OwnerGID:      os.Getgid(),
			APIAddr:       "127.0.0.1:18970",
			ProxyAddr:     "127.0.0.1:4000",
			APIToken:      "test-token",
			OTLPPathToken: strings.Repeat("d", 64),
			GuardrailMode: "action",
			HookFailMode:  "closed",
			AgentVersion:  version,
			Registry:      connector.NewDefaultRegistry(),
			// Protected before: repair may rewrite the existing hook config.
			AllowMissingHookConfigRepair: true,
		}
	}
	first, err := Install(context.Background(), options("codex-cli 0.142.0"))
	if err != nil {
		t.Fatalf("first install: %v", err)
	}
	if first.HookContractID != "codex-hooks-v3-generic" {
		t.Fatalf("first contract = %q, want codex-hooks-v3-generic", first.HookContractID)
	}

	setStandaloneProfileForTest(t, false)
	if _, err := Install(context.Background(), options("codex-cli 0.150.0")); err == nil ||
		!strings.Contains(err.Error(), "hook contract drift detected") {
		t.Fatalf("Secure Client repair after an upgrade = %v, want the drift refusal", err)
	}

	setStandaloneProfileForTest(t, true)
	if _, err := Verify(context.Background(), options("codex-cli 0.150.0")); err == nil {
		t.Fatal("verify after the upgrade passed, want the stale lock reported so the guardian repairs it")
	}
	repaired, err := Install(context.Background(), options("codex-cli 0.150.0"))
	if err != nil {
		t.Fatalf("standalone repair after a verified upgrade: %v", err)
	}
	if repaired.HookContractID != "codex-hooks-v4" || repaired.AgentVersion != "codex-cli 0.150.0" {
		t.Fatalf("repair result = %s at %q, want codex-hooks-v4 at the new version", repaired.HookContractID, repaired.AgentVersion)
	}
	verified, err := Verify(context.Background(), options("codex-cli 0.150.0"))
	if err != nil || verified.HookContractID != "codex-hooks-v4" {
		t.Fatalf("verify after the repair = %+v, %v; want the new contract", verified, err)
	}
	if _, err := Install(context.Background(), options("codex-cli 0.100.0")); err == nil ||
		!strings.Contains(err.Error(), "is not verified against a known hook contract") {
		t.Fatalf("repair to an unverified version = %v, want the hook_contract_unverified refusal", err)
	}
}
