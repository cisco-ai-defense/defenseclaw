// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// GAP-0632: the gateway loads the built-in pack of a broken custom_packs
// entry's name (default for any other name) instead of the embedded pack or
// a refusal, and a writer's check refuses the entry. A usable entry loads its
// own folder.
func TestGAP0632BrokenCustomPackLoadsBuiltinPack(t *testing.T) {
	policies, err := filepath.Abs(filepath.Join("..", "..", "policies"))
	if err != nil {
		t.Fatal(err)
	}
	copyDir := filepath.Join(t.TempDir(), "operator-pack")
	if err := os.CopyFS(copyDir, os.DirFS(filepath.Join(policies, "guardrail", "strict"))); err != nil {
		t.Fatal(err)
	}
	pin, err := guardrail.RulePackDigest(copyDir)
	if err != nil {
		t.Fatal(err)
	}
	builtin := func(name string) string {
		pack, err := guardrail.LoadRulePack(filepath.Join(policies, "guardrail", name))
		if err != nil {
			t.Fatal(err)
		}
		return pack.FilesDigest()
	}
	for _, name := range []string{"operator", "default", "strict"} {
		for variant, entry := range map[string]config.CustomRulePack{
			"whitespace path": {Path: "  ", Digest: "sha256:" + pin},
			"empty file set":  {Path: copyDir, Digest: config.EmptyRulePackFilesDigest},
		} {
			t.Run(variant+"/"+name, func(t *testing.T) {
				cfg := &config.Config{PolicyDir: policies}
				cfg.Guardrail.RulePack = name
				cfg.Guardrail.CustomPacks = map[string]config.CustomRulePack{name: entry}
				loaded, err := loadGlobalRulePack(guardrail.NewRulePackCache(), cfg, "config")
				if err != nil {
					t.Fatalf("load: %v", err)
				}
				fallback := name
				if fallback == "operator" {
					fallback = "default"
				}
				if got, want := loaded.FilesDigest(), builtin(fallback); got != want {
					t.Errorf("loaded files digest %s, want built-in %s pack %s", got, fallback, want)
				}
				err = CheckRulePacks(cfg)
				if err == nil || !strings.Contains(err.Error(), "guardrail.custom_packs."+name) {
					t.Errorf("writer check = %v, want the entry's config error", err)
				}
			})
		}
		t.Run("usable/"+name, func(t *testing.T) {
			cfg := &config.Config{PolicyDir: policies}
			cfg.Guardrail.RulePack = name
			cfg.Guardrail.CustomPacks = map[string]config.CustomRulePack{name: {Path: copyDir, Digest: "sha256:" + pin}}
			loaded, err := loadGlobalRulePack(guardrail.NewRulePackCache(), cfg, "config")
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if got := loaded.FilesDigest(); got != pin {
				t.Errorf("loaded files digest %s, want the custom pack %s", got, pin)
			}
			if err := CheckRulePacks(cfg); err != nil {
				t.Errorf("writer check: %v", err)
			}
		})
	}
}
