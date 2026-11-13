// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	policyassets "github.com/defenseclaw/defenseclaw/policies"
)

const windowsStandaloneConfigPath = `C:\ProgramData\Cisco\DefenseClaw\etc\config.yaml`

func shippedTestConfig(profile, configPath string) *Config {
	cfg := &Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, ConfigFilePath: configPath}
	cfg.Enterprise.Profile = profile
	return cfg
}

// TestWindowsShippedRulePackResolution covers #1445: on a managed Windows
// standalone install strict and permissive resolve to this release's shipped
// folder with no policy_dir; an existing policy_dir folder still wins (an
// upgrade from 1.0.9 with strict and policy_dir keeps working); default
// stays embedded; Secure Client, Linux, macOS and per-user are unchanged.
func TestWindowsShippedRulePackResolution(t *testing.T) {
	root := t.TempDir()
	defer SetWindowsShippedRulePacksRootForTest(root)()
	folderName, err := policyassets.ShippedRulePackFolderName()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := WindowsShippedRulePacksFolder(), filepath.Join(root, folderName); got != want {
		t.Fatalf("shipped folder = %q, want %q", got, want)
	}
	win := shippedTestConfig(managed.ProfileStandalone, windowsStandaloneConfigPath)
	for _, name := range []string{"strict", "permissive"} {
		want := filepath.Join(root, folderName, name)
		if got := win.ResolveRulePackDir(RulePackRef{Name: name}); got != want {
			t.Errorf("%s with no policy_dir = %q, want %q", name, got, want)
		}
		if got := win.WindowsShippedRulePackName(want); got != name {
			t.Errorf("WindowsShippedRulePackName(%q) = %q", want, got)
		}
		if advice := win.WindowsShippedRulePackAdvice(want); !strings.Contains(advice, "/repair") || !strings.Contains(advice, name) {
			t.Errorf("advice for the shipped %s folder = %q, want the repair named", name, advice)
		}
	}
	if got := win.ResolveRulePackDir(RulePackRef{Name: "default"}); got != "" || !win.EmbeddedRulePack(RulePackRef{Name: "default"}) {
		t.Errorf("default = %q, embedded %v; want the embedded pack", got, win.EmbeddedRulePack(RulePackRef{Name: "default"}))
	}

	policyDir := t.TempDir()
	adminStrict := filepath.Join(policyDir, "guardrail", "strict")
	if err := os.MkdirAll(adminStrict, 0o700); err != nil {
		t.Fatal(err)
	}
	win.PolicyDir = policyDir
	if got := win.ResolveRulePackDir(RulePackRef{Name: "strict"}); got != adminStrict {
		t.Errorf("strict with a policy_dir folder = %q, want the administrator's %q", got, adminStrict)
	}
	if advice := win.WindowsShippedRulePackAdvice(adminStrict); advice != "" {
		t.Errorf("the administrator's folder got the shipped advice: %q", advice)
	}
	if got, want := win.ResolveRulePackDir(RulePackRef{Name: "permissive"}), filepath.Join(root, folderName, "permissive"); got != want {
		t.Errorf("permissive with a policy_dir that has no folder for it = %q, want the shipped %q", got, want)
	}
	win.PolicyDir = ""

	for label, cfg := range map[string]*Config{
		"secure client": shippedTestConfig(managed.ProfileSecureClient, windowsStandaloneConfigPath),
		"linux layout":  shippedTestConfig(managed.ProfileStandalone, "/etc/defenseclaw/config.yaml"),
		"per user":      {},
	} {
		if got := cfg.ResolveRulePackDir(RulePackRef{Name: "strict"}); got != "" {
			t.Errorf("%s: strict with no policy_dir = %q, want unchanged \"\"", label, got)
		}
		if got := cfg.WindowsShippedRulePackDir("strict"); got != "" {
			t.Errorf("%s: shipped dir = %q, want none", label, got)
		}
	}

	restore := SetWindowsShippedRulePacksRootForTest("")
	if got := win.ResolveRulePackDir(RulePackRef{Name: "strict"}); got != "" {
		t.Errorf("strict with no trusted root = %q, want \"\"", got)
	}
	restore()
}
