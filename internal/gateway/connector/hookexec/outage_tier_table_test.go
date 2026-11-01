// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// outageTableModes resolves a cell's hook modes with the product's own
// resolvers: a per-user hook loads its config.yaml at call time and asks
// EffectiveHookOutageFailModeForConnector (as hook-outage-mode does); a
// managed hook runs with the mode its render records
// (connector.OutageHookFailMode of EffectiveHookFailModeForConnector).
func outageTableModes(t *testing.T, tier, install, saved string) (string, func() string) {
	t.Helper()
	if install == "oss" {
		home := t.TempDir()
		t.Setenv("DEFENSECLAW_HOME", home)
		t.Setenv("HOME", home)
		body := "config_version: 9\nobservability: {}\nguardrail:\n  mode: observe\n  rule_pack: " + tier + "\n"
		if saved != "" {
			body += "  hook_fail_mode: " + saved + "\n"
		}
		path := filepath.Join(home, config.DefaultConfigName)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return "closed", func() string {
			loaded, err := config.LoadFromFile(path)
			if err != nil {
				t.Errorf("load %s: %v", path, err)
				return "closed"
			}
			return loaded.EffectiveHookOutageFailModeForConnector("codex")
		}
	}
	cfg := &config.Config{}
	cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
	cfg.Enterprise.Profile = managed.ProfileStandalone
	if install == "secure_client" {
		cfg.Enterprise.Profile = managed.ProfileSecureClient
	}
	cfg.Guardrail.RulePack = tier
	cfg.Guardrail.HookFailMode = saved
	return connector.OutageHookFailMode(connector.SetupOpts{
		ManagedEnterprise:        true,
		SecureClientHookDelivery: install == "secure_client",
		HookFailMode:             cfg.EffectiveHookFailModeForConnector("codex"),
	}, nil), nil
}

// The outage rule over policy tier x install type x saved mode x gateway
// answer (135 cells), through the real config resolvers and the native hook
// decision. The expectation is the owner decision of 2026-10-23 written out
// here: an explicit saved mode wins; unset, an OSS install opens an outage
// in the default and permissive tiers and closes it in strict, a managed
// install closes it and Secure Client keeps its open default. A gateway that
// answered (even unusably) is never an outage.
func TestNativeOutageTierInstallAnswerSavedModeTable(t *testing.T) {
	for _, tier := range []string{"permissive", "default", "strict"} {
		for _, install := range []string{"oss", "managed", "secure_client"} {
			for _, saved := range []string{"", "open", "closed"} {
				ruleOpen := saved == "open" ||
					(saved == "" && (install == "secure_client" || (install == "oss" && tier != "strict")))
				for _, answer := range []string{"up", "down", "timeout", "truncated", "malformed"} {
					t.Run(tier+"/"+install+"/"+saved+"/"+answer, func(t *testing.T) {
						failMode, outageNow := outageTableModes(t, tier, install, saved)
						// Secure Client's open mode also covers an unanswered
						// or unusable answer (#1163, unchanged).
						want := answer == "up" || (answer == "down" && ruleOpen) ||
							(install == "secure_client" && ruleOpen && (answer == "timeout" || answer == "malformed"))
						if got := hookexec.NativeOutageCellAllowsForTest(t, install, answer, failMode, outageNow); got != want {
							t.Fatalf("allow=%v, want %v (render mode %q)", got, want, failMode)
						}
					})
				}
			}
		}
	}
}
