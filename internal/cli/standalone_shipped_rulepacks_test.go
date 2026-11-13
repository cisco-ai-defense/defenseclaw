// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func shippedRulePackTestConfig(profile, pack string) *config.Config {
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise,
		ConfigFilePath: `C:\ProgramData\Cisco\DefenseClaw\etc\config.yaml`}
	cfg.Enterprise.Profile = profile
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.RulePack = pack
	return cfg
}

// TestShippedRulePackMissingNamesRepair covers #1445: a managed Windows
// config whose shipped pack folder is missing is refused with the repair
// that writes it; any other folder and Secure Client are left to the loader.
func TestShippedRulePackMissingNamesRepair(t *testing.T) {
	root := t.TempDir()
	defer config.SetWindowsShippedRulePacksRootForTest(root)()
	cfg := shippedRulePackTestConfig("standalone", "strict")
	shipped := cfg.ResolveRulePackDir(config.RulePackRef{Name: "strict"})
	if !strings.HasPrefix(shipped, root) {
		t.Fatalf("strict resolves to %q, want the shipped folder under %s", shipped, root)
	}
	err := shippedRulePackMissing(cfg, "config.yaml", shipped)
	if err == nil || !strings.Contains(err.Error(), "the folder is missing") || !strings.Contains(err.Error(), "/repair") {
		t.Fatalf("missing shipped folder = %v, want the repair named", err)
	}
	if err := os.MkdirAll(shipped, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := shippedRulePackMissing(cfg, "config.yaml", shipped); err != nil {
		t.Errorf("an existing shipped folder was refused: %v", err)
	}
	if err := shippedRulePackMissing(cfg, "config.yaml", filepath.Join(t.TempDir(), "guardrail", "strict")); err != nil {
		t.Errorf("a folder that is not the shipped one was claimed: %v", err)
	}
	secure := shippedRulePackTestConfig("secure_client", "strict")
	if err := shippedRulePackMissing(secure, "config.yaml", shipped); err != nil {
		t.Errorf("secure client got the standalone refusal: %v", err)
	}
}

// TestUseBinaryShippedRulePacksForPreflight covers #1445: before the
// lifecycle writes the shipped folder (a first install, an upgrade to a new
// release), the preflight checks this binary's own copy, and the redirect
// and the copy go when it is done.
func TestUseBinaryShippedRulePacksForPreflight(t *testing.T) {
	root := t.TempDir()
	defer config.SetWindowsShippedRulePacksRootForTest(root)()
	cfg := shippedRulePackTestConfig("standalone", "strict")
	shipped := cfg.ResolveRulePackDir(config.RulePackRef{Name: "strict"})
	if _, err := os.Stat(shipped); !os.IsNotExist(err) {
		t.Fatalf("the shipped folder %s exists before the lifecycle wrote it: %v", shipped, err)
	}
	copyRoot, cleanup, err := useBinaryShippedRulePacks(cfg)
	if err != nil || copyRoot == "" {
		t.Fatalf("useBinaryShippedRulePacks = %q, %v", copyRoot, err)
	}
	if got := cfg.ResolveRulePackDir(config.RulePackRef{Name: "strict"}); !pathWithinFolder(got, copyRoot) {
		t.Fatalf("strict resolves to %q during the preflight, want the copy under %s", got, copyRoot)
	}
	if err := gateway.CheckRulePacks(cfg); err != nil {
		t.Fatalf("this binary's strict pack in the preflight: %v", err)
	}
	loaded, err := guardrail.LoadRulePack(cfg.ResolveRulePackDir(config.RulePackRef{Name: "strict"}))
	if err != nil || loaded.Posture() != "strict" {
		t.Fatalf("the preflight copy of strict = %v, %v", loaded, err)
	}
	cleanup()
	if _, err := os.Stat(copyRoot); !os.IsNotExist(err) {
		t.Errorf("the preflight copy %s stays: %v", copyRoot, err)
	}
	if got := cfg.ResolveRulePackDir(config.RulePackRef{Name: "strict"}); got != shipped {
		t.Errorf("strict resolves to %q after the preflight, want %q", got, shipped)
	}

	none := shippedRulePackTestConfig("standalone", "default")
	if copyRoot, cleanup, err := useBinaryShippedRulePacks(none); err != nil || copyRoot != "" {
		t.Errorf("a config with no shipped pack got a copy %q, %v", copyRoot, err)
	} else {
		cleanup()
	}
}

// TestShippedRulePacksWriteRequired covers #1445 review P1: a failed write of
// the shipped packs fails the lifecycle only when the config it applies
// selects strict or permissive (or cannot be read); a default-pack
// deployment, an administrator's policy_dir pack and Secure Client go on.
func TestShippedRulePacksWriteRequired(t *testing.T) {
	root := t.TempDir()
	defer config.SetWindowsShippedRulePacksRootForTest(root)()
	for _, tc := range []struct {
		name string
		cfg  *config.Config
		err  error
		want bool
	}{
		{"default pack", shippedRulePackTestConfig("standalone", "default"), nil, false},
		{"no rule_pack", shippedRulePackTestConfig("standalone", ""), nil, false},
		{"strict", shippedRulePackTestConfig("standalone", "strict"), nil, true},
		{"permissive", shippedRulePackTestConfig("standalone", "permissive"), nil, true},
		{"secure client strict", shippedRulePackTestConfig("secure_client", "strict"), nil, false},
		{"unreadable config", nil, os.ErrNotExist, true},
	} {
		if got := shippedRulePacksWriteRequired(tc.cfg, tc.err); got != tc.want {
			t.Errorf("%s: required = %v, want %v", tc.name, got, tc.want)
		}
	}
	profile := shippedRulePackTestConfig("standalone", "default")
	profile.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"codex": {RulePack: "strict"}}
	if got := configSelectsShippedRulePack(profile); got != "strict" {
		t.Errorf("a connector that selects strict = %q, want strict", got)
	}
	admin := shippedRulePackTestConfig("standalone", "strict")
	admin.PolicyDir = t.TempDir()
	if err := os.MkdirAll(filepath.Join(admin.PolicyDir, "guardrail", "strict"), 0o700); err != nil {
		t.Fatal(err)
	}
	if shippedRulePacksWriteRequired(admin, nil) {
		t.Error("strict from the administrator's policy_dir needs no shipped folder")
	}
}
