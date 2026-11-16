// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0632: a broken custom_packs entry is one config error that every reader
// shares. Its selection loads the built-in pack of its name (default for any
// other name) and never opens a hook outage, on a per-user and a managed
// install. A usable entry keeps its own folder and posture.
func TestGAP0632BrokenCustomPackFallsBackToBuiltinPack(t *testing.T) {
	policyDir := t.TempDir()
	for _, name := range BuiltinRulePacks {
		if err := os.MkdirAll(filepath.Join(policyDir, "guardrail", name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	pack := t.TempDir()
	if err := os.WriteFile(filepath.Join(pack, "suppressions.yaml"), []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "pack.yaml")
	if err := os.WriteFile(file, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pin := "sha256:" + strings.Repeat("a", 64)
	broken := map[string]CustomRulePack{
		"whitespace path":   {Path: " \t ", Digest: pin},
		"empty file set":    {Path: pack, Digest: EmptyRulePackFilesDigest},
		"missing folder":    {Path: filepath.Join(pack, "missing"), Digest: pin},
		"file, not folder":  {Path: file, Digest: pin},
		"upper-case digest": {Path: pack, Digest: strings.ToUpper(EmptyRulePackFilesDigest)},
	}
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		unreadable := filepath.Join(t.TempDir(), "unreadable")
		if err := os.Mkdir(unreadable, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(unreadable, 0o700) })
		broken["unreadable folder"] = CustomRulePack{Path: unreadable, Digest: pin}
	}
	for _, deployment := range []string{"", managed.DeploymentModeManagedEnterprise} {
		for variant, entry := range broken {
			for _, name := range []string{"operator", "default", "strict", "permissive"} {
				t.Run(deployment+"/"+variant+"/"+name, func(t *testing.T) {
					cfg := &Config{PolicyDir: policyDir, DeploymentMode: deployment}
					if deployment != "" {
						cfg.Enterprise.Profile = managed.ProfileStandalone
					}
					cfg.Guardrail.RulePack = name
					cfg.Guardrail.CustomPacks = map[string]CustomRulePack{name: entry}
					cfg.CheckCustomRulePacks()
					problem := cfg.CustomRulePackError(name)
					if problem == nil || !strings.Contains(problem.Error(), "guardrail.custom_packs."+name) {
						t.Fatalf("config error = %v", problem)
					}
					if errs := cfg.CustomRulePackErrors(); len(errs) != 1 || errs[0] != problem {
						t.Fatalf("config errors = %v", errs)
					}
					fallback := name
					if !IsBuiltinRulePack(name) {
						fallback = "default"
					}
					ref := RulePackRef{Name: name}
					if got, want := cfg.ResolveRulePackDir(ref), filepath.Join(policyDir, "guardrail", fallback); got != want {
						t.Errorf("pack dir = %q, want built-in %q", got, want)
					}
					if got := cfg.BuiltinRulePackFor(name); got != fallback {
						t.Errorf("built-in fallback = %q, want %q", got, fallback)
					}
					if got := cfg.HookPolicyTierForConnector("codex"); got != HookPolicyTierStrict {
						t.Errorf("tier = %q, want strict", got)
					}
					if got := cfg.EffectiveHookOutageFailModeForConnector("codex"); got != "closed" {
						t.Errorf("outage mode = %q, want closed", got)
					}
					embedded := &Config{DeploymentMode: deployment}
					embedded.Enterprise.Profile = cfg.Enterprise.Profile
					embedded.Guardrail.CustomPacks = map[string]CustomRulePack{name: entry}
					if got, want := embedded.EmbeddedRulePack(ref), fallback == "default"; got != want {
						t.Errorf("embedded fallback = %v, want %v", got, want)
					}
				})
			}
		}
	}

	t.Run("Secure Client unchanged", func(t *testing.T) {
		cfg := &Config{PolicyDir: policyDir, DeploymentMode: managed.DeploymentModeManagedEnterprise}
		cfg.Guardrail.RulePack = "strict"
		cfg.Guardrail.CustomPacks = map[string]CustomRulePack{"strict": {Path: file, Digest: pin}}
		cfg.CheckCustomRulePacks()
		if !cfg.SecureClientIntegration() || cfg.CustomRulePackError("strict") != nil {
			t.Fatal("Secure Client entry judged by the shared check")
		}
		if got := cfg.ResolveRulePackDir(RulePackRef{Name: "strict"}); got != file {
			t.Errorf("Secure Client pack dir = %q, want the entry's own path", got)
		}
	})

	t.Run("usable entry", func(t *testing.T) {
		for _, name := range []string{"operator", "default", "strict"} {
			cfg := &Config{PolicyDir: policyDir}
			cfg.Guardrail.RulePack = name
			cfg.Guardrail.CustomPacks = map[string]CustomRulePack{name: {Path: pack + "/", Digest: pin}}
			cfg.CheckCustomRulePacks()
			if err := cfg.CustomRulePackError(name); err != nil || len(cfg.CustomRulePackErrors()) != 0 {
				t.Fatalf("%s: usable entry error = %v", name, err)
			}
			if got := cfg.ResolveRulePackDir(RulePackRef{Name: name}); got != pack+"/" {
				t.Errorf("%s: pack dir = %q, want the custom folder", name, got)
			}
			if got := cfg.BuiltinRulePackFor(name); got != "" {
				t.Errorf("%s: built-in fallback = %q, want none", name, got)
			}
		}
	})

	t.Run("checked once at load", func(t *testing.T) {
		moving := filepath.Join(t.TempDir(), "pack")
		if err := os.Mkdir(moving, 0o700); err != nil {
			t.Fatal(err)
		}
		cfg := &Config{PolicyDir: policyDir}
		cfg.Guardrail.RulePack = "operator"
		cfg.Guardrail.CustomPacks = map[string]CustomRulePack{"operator": {Path: moving, Digest: pin}}
		cfg.CheckCustomRulePacks()
		if err := os.Remove(moving); err != nil {
			t.Fatal(err)
		}
		if got := cfg.ResolveRulePackDir(RulePackRef{Name: "operator"}); got != moving {
			t.Errorf("loaded usable entry now resolves to %q", got)
		}
		cfg.Guardrail.CustomPacks["operator"] = CustomRulePack{Path: " ", Digest: pin}
		if cfg.CustomRulePackError("operator") == nil {
			t.Error("an entry edited after load is not checked again")
		}
	})
}
