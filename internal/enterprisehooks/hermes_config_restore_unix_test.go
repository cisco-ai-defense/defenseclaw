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

// GAP-0564: the standalone guardian's repair of a missing ~/.hermes/config.yaml
// wrote the hooks key alone, so the account's model and Bedrock settings were
// gone and the guardian state said nothing. The per-user worker's verify that
// passes keeps the file as the last known good copy; the repair puts it back
// with the hooks and says so in its result, which the guardian records for
// the enterprise status and verify.
func TestStandaloneRepairPutsBackAMissingHermesConfigWithTheAccountsSettings(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	setStandaloneProfileForTest(t, true)
	home := newTestHome(t)
	opts := hermesStandaloneOptions(t, home)
	configPath := filepath.Join(home, ".hermes", "config.yaml")
	if err := os.WriteFile(configPath, []byte("model:\n  default: us.anthropic.claude-haiku-4-5\n  provider: bedrock\nbedrock:\n  region: us-east-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("install: %v", err)
	}
	verified, err := Verify(context.Background(), opts)
	if err != nil || verified.AgentConfig != "" {
		t.Fatalf("verify after install = %q %v", verified.AgentConfig, err)
	}
	if err := os.Rename(configPath, configPath+".bak"); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), opts); err == nil {
		t.Fatal("verify passed with config.yaml gone")
	}
	repair := opts
	repair.AllowMissingHookConfigRepair = true
	repaired, err := Install(context.Background(), repair)
	if err != nil {
		t.Fatalf("repair: %v", err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"model:", "bedrock:", "hooks:", "us.anthropic.claude-haiku-4-5"} {
		if !strings.Contains(string(data), key) {
			t.Fatalf("repaired config.yaml lacks %q:\n%s", key, data)
		}
	}
	if repaired.AgentConfig != connector.AgentConfigRestoredLastGood {
		t.Fatalf("repair agent config status = %q", repaired.AgentConfig)
	}
	verified, err = Verify(context.Background(), opts)
	if err != nil || verified.AgentConfig != "" {
		t.Fatalf("verify after the repair = %q %v", verified.AgentConfig, err)
	}
}
