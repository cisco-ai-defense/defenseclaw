// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func copyShippedPack(t *testing.T, name, dir string) string {
	t.Helper()
	if err := os.CopyFS(dir, os.DirFS(filepath.Join(guardrailPoliciesRoot(t), name))); err != nil {
		t.Fatal(err)
	}
	pin, err := guardrail.RulePackDigest(dir)
	if err != nil {
		t.Fatal(err)
	}
	return "sha256:" + pin
}

// GAP-0632: a pack the gateway loaded keeps its posture for a caller that holds
// only the guardrail block, whatever happens to its source folder afterwards
// (the Secure Client decision path), and a custom pack that is used keeps its
// own posture.
func TestGAP0632SecureClientKeepsLoadedStrictPosture(t *testing.T) {
	withManagedEnterprise(t, true)
	dir := filepath.Join(t.TempDir(), "strict")
	pin := copyShippedPack(t, "strict", dir)
	gc := &config.GuardrailConfig{RulePack: "operator", CustomPacks: map[string]config.CustomRulePack{
		"operator": {Path: dir, Digest: pin},
	}}
	rememberPackPosture(dir, "strict")
	if got := guardrailContentActionForGuardrail(gc, "codex", "HIGH"); got != guardrailActionBlock {
		t.Fatalf("before removal: action %q, want block", got)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if got := guardrailContentActionForGuardrail(gc, "codex", "HIGH"); got != guardrailActionBlock {
		t.Errorf("after removal: action %q, want the loaded strict block", got)
	}
}

// GAP-0632: every reader that holds only the guardrail block resolves a
// broken entry to the same built-in fallback as the configuration does: a
// broken entry named like a built-in pack keeps that pack's levels, any other
// the default levels; a built-in name has its own levels; a usable pinned
// copy of the default pack keeps the default levels.
func TestGAP0632GuardrailOnlyThresholdsFollowTheFallback(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(fmt.Sprintf("secure client %v", active), func(t *testing.T) {
			withManagedEnterprise(t, active)
			good := filepath.Join(t.TempDir(), "pack")
			goodPin := copyShippedPack(t, "default", good)
			missing := filepath.Join(t.TempDir(), "pack")
			badPin := "sha256:" + strings.Repeat("a", 64)
			for _, row := range []struct {
				name, selected string
				entry          *config.CustomRulePack
				want           string
				wantSC         string
			}{
				{name: "built-in strict", selected: "strict", want: guardrailActionBlock},
				{name: "built-in default", selected: "default", want: guardrailActionAlert},
				{name: "built-in permissive", selected: "permissive", want: guardrailActionAlert},
				{name: "broken strict-named entry", selected: "strict", entry: &config.CustomRulePack{Path: missing, Digest: badPin}, want: guardrailActionBlock, wantSC: guardrailActionAlert},
				{name: "broken other-named entry", selected: "operator", entry: &config.CustomRulePack{Path: missing, Digest: badPin}, want: guardrailActionAlert},
				{name: "usable pinned default copy", selected: "operator", entry: &config.CustomRulePack{Path: good, Digest: goodPin}, want: guardrailActionAlert},
			} {
				gc := &config.GuardrailConfig{RulePack: row.selected}
				if row.entry != nil {
					gc.CustomPacks = map[string]config.CustomRulePack{row.selected: *row.entry}
				}
				want := row.want
				if active && row.wantSC != "" {
					// The Secure Client integration keeps its loader's own
					// refusals: an entry always names its folder.
					want = row.wantSC
				}
				if got := guardrailContentActionForGuardrail(gc, "codex", "HIGH"); got != want {
					t.Errorf("%s: HIGH action %q, want %q", row.name, got, want)
				}
			}
		})
	}
}

// GAP-0632: the config-load check reads the pack the way the gateway loads
// it: a folder with no files, a pack with a malformed component and a pack
// whose files do not hash to the pin each are one config error and a strict
// (closed) hook tier, whatever the pin string. The first two load the built-in
// fallback pack; a stale pin is an integrity refusal instead: the entry stays
// the selected pack and the gateway refuses it.
func TestGAP0632InvalidContentIsConfigErrorAndBuiltinFallback(t *testing.T) {
	policies := filepath.Dir(guardrailPoliciesRoot(t))
	for _, variant := range []string{"empty folder", "invalid component", "wrong pin"} {
		t.Run(variant, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "pack")
			pin := "sha256:" + strings.Repeat("a", 64)
			switch variant {
			case "empty folder":
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			case "invalid component":
				if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o700); err != nil {
					t.Fatal(err)
				}
				content := []byte("rules: [\n")
				if err := os.WriteFile(filepath.Join(dir, "rules", "broken.yaml"), content, 0o600); err != nil {
					t.Fatal(err)
				}
				fileSum := sha256.Sum256(content)
				h := sha256.New()
				_, _ = fmt.Fprintf(h, "rules/broken.yaml\n%s\n", hex.EncodeToString(fileSum[:]))
				pin = "sha256:" + hex.EncodeToString(h.Sum(nil))
			case "wrong pin":
				copyShippedPack(t, "default", dir)
			}
			cfg := &config.Config{PolicyDir: policies}
			cfg.Guardrail.RulePack = "operator"
			cfg.Guardrail.CustomPacks = map[string]config.CustomRulePack{"operator": {Path: dir, Digest: pin}}
			if problems := cfg.CustomRulePackErrors(); len(problems) != 1 || !strings.Contains(problems[0].Error(), "guardrail.custom_packs.operator") {
				t.Errorf("config errors = %v, want one naming the entry", problems)
			}
			stale := variant == "wrong pin"
			if stale != config.IsStalePinError(cfg.CustomRulePackError("operator")) {
				t.Errorf("config error %v: stale pin = %v, want %v", cfg.CustomRulePackError("operator"), !stale, stale)
			}
			wantFallback := "default"
			if stale {
				wantFallback = ""
			}
			if got := cfg.BuiltinRulePackFor("operator"); got != wantFallback {
				t.Errorf("fallback = %q, want %q", got, wantFallback)
			}
			if got := cfg.HookPolicyTierForConnector("codex"); got != config.HookPolicyTierStrict {
				t.Errorf("tier = %q, want strict", got)
			}
			if got := cfg.EffectiveHookOutageFailModeForConnector("codex"); got != "closed" {
				t.Errorf("outage mode = %q, want closed", got)
			}
			loaded, err := loadGlobalRulePack(guardrail.NewRulePackCache(), cfg, "config")
			if stale {
				if err == nil || !strings.Contains(err.Error(), "custom_packs pin") {
					t.Errorf("gateway load of a stale pin = %v, want the digest refusal", err)
				}
				if err := CheckRulePacks(cfg); err == nil {
					t.Error("the writer check accepted a stale pin")
				}
				return
			}
			if err != nil {
				t.Fatalf("gateway load = %v, want the built-in fallback", err)
			}
			builtin, err := guardrail.LoadRulePack(filepath.Join(policies, "guardrail", "default"))
			if err != nil {
				t.Fatal(err)
			}
			if loaded.FilesDigest() != builtin.FilesDigest() {
				t.Errorf("loaded digest %s, want built-in default %s", loaded.FilesDigest(), builtin.FilesDigest())
			}
			if err := CheckRulePacks(cfg); err == nil {
				t.Error("the writer check accepted a broken entry")
			}
		})
	}
}

// GAP-0632: a relative custom_packs path is relative to the directory of the
// config file that declares it, in every reader, whatever the working
// directory of the gateway or the hook is.
func TestGAP0632RelativeCustomPackUsesConfigDirectory(t *testing.T) {
	configDir := t.TempDir()
	packDir := filepath.Join(configDir, "pack")
	pin := copyShippedPack(t, "default", packDir)
	t.Chdir(t.TempDir())
	cfg := &config.Config{ConfigFilePath: filepath.Join(configDir, "config.yaml"), PolicyDir: filepath.Dir(guardrailPoliciesRoot(t))}
	cfg.Guardrail.RulePack = "operator"
	cfg.Guardrail.CustomPacks = map[string]config.CustomRulePack{"operator": {Path: "pack", Digest: pin}}
	for _, recorded := range []bool{false, true} {
		if recorded {
			cfg.CheckCustomRulePacks()
		}
		if err := cfg.CustomRulePackError("operator"); err != nil {
			t.Errorf("recorded %v: valid config-relative folder: %v", recorded, err)
		}
		if got := cfg.ResolveRulePackDir(config.RulePackRef{Name: "operator"}); got != packDir {
			t.Errorf("recorded %v: resolved path = %q, want %q", recorded, got, packDir)
		}
		if got := cfg.ReferencedRulePackDirs()["guardrail.custom_packs.operator.path"]; got != packDir {
			t.Errorf("recorded %v: referenced path = %q, want %q", recorded, got, packDir)
		}
		loaded, err := loadGlobalRulePack(guardrail.NewRulePackCache(), cfg, "config")
		if err != nil || loaded.FilesDigest() != strings.TrimPrefix(pin, "sha256:") {
			t.Errorf("recorded %v: gateway load = %v, %v; want the custom copy", recorded, loaded, err)
		}
	}
}

// GAP-0632: a relative config path is legal, and the folder a relative
// custom_packs path names is fixed when the configuration is loaded: a later
// change of working directory leaves the selected pack, and the writer check
// that vouched for it, on the same folder. The ordinary twin is the absolute
// config path of the test above.
func TestGAP0632RelativeConfigPathSurvivesChdir(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "cfg"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	pin := copyShippedPack(t, "strict", filepath.Join("cfg", "pack"))
	policyDir := filepath.Dir(guardrailPoliciesRoot(t))
	raw := fmt.Sprintf("config_version: 9\ndata_dir: %q\npolicy_dir: %q\nguardrail:\n  enabled: true\n  mode: action\n  rule_pack: operator\n  custom_packs:\n    operator:\n      path: pack\n      digest: %q\n", root, policyDir, pin)
	if err := os.WriteFile(filepath.Join("cfg", "config.yaml"), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	built := &config.Config{ConfigFilePath: filepath.Join("cfg", "config.yaml"), PolicyDir: policyDir}
	built.Guardrail.RulePack = "operator"
	built.Guardrail.CustomPacks = map[string]config.CustomRulePack{"operator": {Path: "pack", Digest: pin}}
	built.CheckCustomRulePacks()
	loaded, err := config.LoadFromFile(filepath.Join("cfg", "config.yaml"))
	if err != nil {
		t.Fatalf("valid relative config file rejected at load: %v", err)
	}
	copied, err := loaded.DeepCopy()
	if err != nil {
		t.Fatal(err)
	}
	for who, cfg := range map[string]*config.Config{"built": built, "loaded": loaded, "copy": copied} {
		if err := cfg.CustomRulePackError("operator"); err != nil {
			t.Fatalf("%s: %v", who, err)
		}
		if err := CheckRulePacks(cfg); err != nil {
			t.Fatalf("%s: valid config-relative pack refused by the writer check: %v", who, err)
		}
	}
	t.Chdir(t.TempDir())
	want := filepath.Join(root, "cfg", "pack")
	for who, cfg := range map[string]*config.Config{"built": built, "loaded": loaded, "copy": copied} {
		got := cfg.ResolveRulePackDir(config.RulePackRef{Name: "operator"})
		if resolved, err := filepath.EvalSymlinks(got); err != nil {
			t.Errorf("%s: selected %q: %v", who, got, err)
		} else if wantResolved, _ := filepath.EvalSymlinks(want); resolved != wantResolved {
			t.Errorf("%s: selected %q after chdir, want %q", who, got, want)
		}
		if _, err := guardrail.LoadRulePack(got); err != nil {
			t.Errorf("%s: config-relative pack changed with the working directory: %v", who, err)
		}
		if err := CheckRulePacks(cfg); err != nil {
			t.Errorf("%s: writer check changed with the working directory: %v", who, err)
		}
	}
}
