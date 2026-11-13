// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Test lanes: one that may be on, one that ships shadow-only.
func init() {
	RegisterCascadeLane(CascadeLane{Name: "test_live", Default: CascadeLaneShadow, Description: "test lane"})
	RegisterCascadeLane(CascadeLane{Name: "test_shadow_only", Default: CascadeLaneShadow, ShadowOnly: "open review findings TEST-1"})
}

func loadCascadeDoc(t *testing.T, body string) *Config {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("DEFENSECLAW_HOME", filepath.Join(home, ".defenseclaw"))
	return loadCascadeDocIn(t, filepath.Join(home, "state"), body)
}

func loadCascadeDocIn(t *testing.T, dataDir, body string) *Config {
	t.Helper()
	raw := []byte("config_version: 9\ndata_dir: " + dataDir + "\n" + body)
	if _, err := ParseCompileObservabilityV8("config.yaml", raw, ObservabilityV8CompileOptions{DefaultDataDir: dataDir}); err != nil {
		t.Fatalf("schema rejected the document: %v\n%s", err, raw)
	}
	cfg, err := LoadRuntimeV8FromBytes("config.yaml", raw)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return cfg
}

func TestCascadeEmptyIsDefault(t *testing.T) {
	cfg := loadCascadeDoc(t, "guardrail:\n  enabled: true\n")
	for _, connector := range []string{"", "codex", "claudecode"} {
		e := cfg.ResolveCascade(connector)
		if !e.IsDefault() {
			t.Fatalf("ResolveCascade(%q) = %+v, want the defaults", connector, e)
		}
		if e.Unknown != CascadeUnknownPack || e.JudgeMaxAction != CascadeBlock || e.JudgeNoVerdict != CascadeFromRules ||
			e.SystemOneOnUnsure != CascadeConfirm || e.CriticalFloor != CascadeAlert || e.PolicyActive {
			t.Fatalf("defaults drifted: %+v", e)
		}
		if e.SystemOneAllowThreshold != DefaultDecisionModelAllowThreshold || e.SystemOneBlockThreshold != DefaultDecisionModelBlockThreshold ||
			e.SystemOneBlockRiskScore != DefaultDecisionModelBlockRiskScore || !e.SystemOneEscalateFlagged {
			t.Fatalf("System One routing is not decision_model's: %+v", e)
		}
	}
	if cfg.Guardrail.Cascade.Invalid() != nil {
		t.Fatal("an empty cascade was reported invalid")
	}
	out, err := yaml.Marshal(cfg.Guardrail)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "cascade") {
		t.Fatalf("an empty cascade was written:\n%s", out)
	}
}

func TestCascadeScopesAndPrecedence(t *testing.T) {
	cfg := loadCascadeDoc(t, `decision_model:
  allow_threshold: 0.2
guardrail:
  enabled: true
  cascade:
    unknown: confirm
    judge:
      max_action: alert
    system_one:
      on_unsure: alert
    lanes:
      test_live: on
  connectors:
    codex:
      cascade:
        unknown: block
        system_one:
          block_threshold: 0.9
          escalate_rule_flagged: false
  profiles:
    contractors:
      cascade:
        judge:
          block_needs_system_one: true
      connectors:
        codex:
          cascade:
            judge:
              max_action: confirm
            lanes:
              test_live: off
`)
	base := cfg.ResolveCascadeExplained("codex")
	if base.Unknown != "block" || base.JudgeMaxAction != "alert" || base.SystemOneOnUnsure != "alert" ||
		base.SystemOneBlockThreshold != 0.9 || base.SystemOneEscalateFlagged || base.SystemOneAllowThreshold != 0.2 {
		t.Fatalf("codex = %+v", base)
	}
	if base.Sources["unknown"] != "guardrail.connectors.codex.cascade.unknown" ||
		base.Sources["system_one.allow_threshold"] != "decision_model.allow_threshold" ||
		base.Sources["judge.max_action"] != "guardrail.cascade.judge.max_action" {
		t.Fatalf("sources = %v", base.Sources)
	}
	if got := cfg.ResolveCascade("cursor"); got.Unknown != "confirm" || got.SystemOneBlockThreshold != DefaultDecisionModelBlockThreshold || got.LaneMode("test_live") != "on" {
		t.Fatalf("cursor = %+v", got)
	}
	derived, err := cfg.DerivedForProfile("contractors")
	if err != nil {
		t.Fatal(err)
	}
	p := derived.ResolveCascadeExplained("codex")
	if !p.JudgeBlockNeedsSystemOne || p.JudgeMaxAction != "confirm" || p.Unknown != "block" || p.LaneMode("test_live") != "off" {
		t.Fatalf("profile codex = %+v", p)
	}
	if p.Sources["judge.max_action"] != "guardrail.profiles.contractors.connectors.codex.cascade.judge.max_action" {
		t.Fatalf("profile sources = %v", p.Sources)
	}
	if q := derived.ResolveCascade("cursor"); q.JudgeMaxAction != "alert" || !q.JudgeBlockNeedsSystemOne || q.LaneMode("test_live") != "on" {
		t.Fatalf("profile cursor = %+v", q)
	}
}

func TestCascadeValidation(t *testing.T) {
	tests := []struct {
		name, body, want string
	}{
		{"unknown below alert", "  cascade:\n    unknown: allow\n", "never below alert"},
		{"unknown log", "  cascade:\n    unknown: log\n", "never below alert"},
		{"bad judge action", "  cascade:\n    judge:\n      max_action: deny\n", "judge.max_action"},
		{"routing at top", "  cascade:\n    system_one:\n      block_threshold: 0.9\n", "set it in decision_model.block_threshold"},
		{"unknown lane", "  cascade:\n    lanes:\n      nope: on\n", "lanes.nope: no such lane"},
		{"shadow-only lane on", "  cascade:\n    lanes:\n      test_shadow_only: on\n", "ships shadow-only (open review findings TEST-1)"},
		{"bad lane value", "  cascade:\n    lanes:\n      test_live: live\n", "not one of off, shadow, on"},
		{"bad lock", "  cascade:\n    admin:\n      locked: [everything]\n", "not a lockable key"},
		{"policy limits without module", "  cascade:\n    policy:\n      lowest: allow\n", "need a module"},
		{"policy lowest above highest", "  cascade:\n    policy:\n      module: {path: /x.rego, digest: \"sha256:" + strings.Repeat("0", 64) + "\"}\n      lowest: confirm\n      highest: alert\n", "lowest \"confirm\" is above highest \"alert\""},
		{"module missing", "  cascade:\n    policy:\n      module: {path: /nonexistent/cascade.rego, digest: \"sha256:" + strings.Repeat("0", 64) + "\"}\n", "guardrail.cascade.policy.module"},
		{"locked at connector", "  cascade:\n    admin:\n      locked: [unknown]\n  connectors:\n    codex:\n      cascade:\n        unknown: block\n", "guardrail.connectors.codex.cascade.unknown: \"unknown\" is locked"},
		{"locked released key in profile", "  cascade:\n    admin:\n      locked: [block_at]\n  profiles:\n    p1:\n      block_at: CRITICAL\n", "guardrail.profiles.p1.block_at: \"block_at\" is locked"},
		{"lock group", "  cascade:\n    admin:\n      locked: [judge]\n  connectors:\n    codex:\n      cascade:\n        judge:\n          no_verdict: unknown\n", "\"judge.no_verdict\" is locked"},
		{"lock all", "  cascade:\n    admin:\n      locked: [\"*\"]\n  connectors:\n    codex:\n      cascade:\n        lanes:\n          test_live: off\n", "\"lanes.test_live\" is locked"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := loadCascadeDoc(t, "guardrail:\n  enabled: true\n"+tt.body)
			inv := cfg.Guardrail.Cascade.Invalid()
			if inv == nil {
				t.Fatalf("cascade accepted, want an error containing %q", tt.want)
			}
			if !strings.Contains(inv.Error, tt.want) {
				t.Fatalf("error = %q, want %q", inv.Error, tt.want)
			}
			if inv.Fallback != CascadeFallbackPack {
				t.Fatalf("fallback = %q, want the pack defaults (nothing saved)", inv.Fallback)
			}
			for _, connector := range []string{"", "codex"} {
				if e := cfg.ResolveCascade(connector); !e.IsDefault() {
					t.Fatalf("invalid cascade still decides: %+v", e)
				}
			}
			if !strings.Contains(inv.Message(), "the rule pack defaults") {
				t.Fatalf("message = %q", inv.Message())
			}
		})
	}
}

func TestCascadeCandidateRefused(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("DEFENSECLAW_HOME", filepath.Join(home, ".defenseclaw"))
	raw := []byte("config_version: 9\ndata_dir: " + filepath.Join(home, "state") + "\nguardrail:\n  cascade:\n    unknown: allow\n")
	err := ValidateCandidate(filepath.Join(home, "config.yaml"), raw)
	var semantic *V8SemanticError
	if !errors.As(err, &semantic) || semantic.Path != "$.guardrail.cascade" || !strings.Contains(err.Error(), "never below alert") {
		t.Fatalf("ValidateCandidate = %v, want the cascade refusal", err)
	}
}

func writeModule(t *testing.T, dir, src string) (string, string) {
	t.Helper()
	path := filepath.Join(dir, "cascade.rego")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(src))
	return path, "sha256:" + hex.EncodeToString(sum[:])
}

func TestCascadePolicyModuleAndLastKnownGood(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("DEFENSECLAW_HOME", filepath.Join(home, ".defenseclaw"))
	dataDir := filepath.Join(home, "state")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	src := "package defenseclaw.cascade\n"
	path, digest := writeModule(t, home, src)
	good := "guardrail:\n  cascade:\n    unknown: block\n    admin:\n      critical_floor: block\n    policy:\n      module: {path: " + path + ", digest: \"" + digest + "\"}\n      lowest: log\n  connectors:\n    codex:\n      cascade:\n        unknown: confirm\n"
	cfg := loadCascadeDocIn(t, dataDir, good)
	if inv := cfg.Guardrail.Cascade.Invalid(); inv != nil {
		t.Fatalf("valid cascade refused: %s", inv.Error)
	}
	e := cfg.ResolveCascade("")
	if !e.PolicyActive || e.PolicyLowest != "log" || string(cfg.Guardrail.Cascade.PolicySource()) != src {
		t.Fatalf("policy = %+v", e)
	}
	if err := WriteCascadeLastGood(cfg); err != nil {
		t.Fatal(err)
	}
	// The module is edited under its pin: the cascade is invalid, and the
	// last-known-good one (with the module source it verified) decides.
	if err := os.WriteFile(path, []byte(src+"# edited\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	broken := loadCascadeDocIn(t, dataDir, good)
	inv := broken.Guardrail.Cascade.Invalid()
	if inv == nil || inv.Fallback != CascadeFallbackLastGood || !strings.Contains(inv.Error, "digest mismatch") {
		t.Fatalf("invalid = %+v, want the last-known-good fallback for a digest mismatch", inv)
	}
	if got := broken.ResolveCascade("codex"); got.Unknown != "confirm" || !got.PolicyActive || got.CriticalFloor != "block" {
		t.Fatalf("last-known-good not applied: %+v", got)
	}
	if len(inv.Weaker) != 0 {
		t.Fatalf("the last-known-good copy of the same intent was reported weaker: %v", inv.Weaker)
	}
	// A different intent that is invalid: the fallback is the saved one,
	// and what the new intent asked for that it lacks is named.
	stricter := "guardrail:\n  cascade:\n    unknown: block\n    admin:\n      critical_floor: block\n      locked: [nope]\n"
	other := loadCascadeDocIn(t, dataDir, stricter)
	inv = other.Guardrail.Cascade.Invalid()
	if inv == nil || inv.Fallback != CascadeFallbackLastGood || !strings.Contains(inv.Message(), "WEAKER") ||
		!strings.Contains(inv.Message(), "admin.locked") {
		t.Fatalf("invalid = %+v (%s)", inv, inv.Message())
	}
	// No saved copy: the pack defaults, named weaker where the intent was stricter.
	if err := os.Remove(filepath.Join(dataDir, CascadeLastGoodFile)); err != nil {
		t.Fatal(err)
	}
	none := loadCascadeDocIn(t, dataDir, stricter)
	inv = none.Guardrail.Cascade.Invalid()
	if inv == nil || inv.Fallback != CascadeFallbackPack || !strings.Contains(strings.Join(inv.Weaker, ";"), "unknown block is not in effect") ||
		!strings.Contains(strings.Join(inv.Weaker, ";"), "critical_floor block") {
		t.Fatalf("invalid = %+v", inv)
	}
	// An empty cascade removes the saved copy (the pack defaults need none).
	if err := WriteCascadeLastGood(cfg); err != nil {
		t.Fatal(err)
	}
	empty := loadCascadeDocIn(t, dataDir, "guardrail:\n  enabled: true\n")
	if err := WriteCascadeLastGood(empty); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, CascadeLastGoodFile)); !os.IsNotExist(err) {
		t.Fatalf("saved copy kept for an empty cascade: %v", err)
	}
}

func TestCascadeDigestUnchangedWithoutCascade(t *testing.T) {
	cfg := loadCascadeDoc(t, "guardrail:\n  enabled: true\n  block_at: HIGH\n  connectors:\n    codex:\n      mode: action\n")
	before, err := GuardrailPolicyDigest(cfg)
	if err != nil {
		t.Fatal(err)
	}
	copyCfg := *cfg
	copyCfg.Guardrail.Cascade = CascadeConfig{}
	if after, _ := GuardrailPolicyDigest(&copyCfg); after != before {
		t.Fatal("digest depends on an empty cascade")
	}
	copyCfg.Guardrail.Cascade.Unknown = CascadeBlock
	if after, _ := GuardrailPolicyDigest(&copyCfg); after == before {
		t.Fatal("digest ignores guardrail.cascade")
	}
}

func TestCascadeProfileMeetStrictest(t *testing.T) {
	yes := true
	members := []*CascadeScope{
		{Unknown: "confirm", Judge: CascadeJudgeConfig{MaxAction: "alert", BlockNeedsSystemOne: &yes}},
		{Judge: CascadeJudgeConfig{MaxAction: "log", NoVerdict: "unknown", BlockNeedsSystemOne: &yes}, SystemOne: CascadeSystemOneConfig{OnUnsure: "rules"}},
	}
	got := strictestCascadeScope(members)
	if got.Unknown != "confirm" || got.Judge.MaxAction != "alert" || got.Judge.NoVerdict != "unknown" ||
		got.Judge.BlockNeedsSystemOne == nil || !*got.Judge.BlockNeedsSystemOne || got.SystemOne.OnUnsure != "confirm" {
		t.Fatalf("meet = %+v", got)
	}
	if strictestCascadeScope([]*CascadeScope{nil, {}}) != nil {
		t.Fatal("meet of members without a cascade has one")
	}
	if m := strictestCascadeScope([]*CascadeScope{{Unknown: "alert"}, nil}); m.Unknown != CascadeUnknownPack || m.Judge.MaxAction != CascadeBlock {
		t.Fatalf("a member without a cascade keeps the defaults: %+v", m)
	}
}

func TestCascadeSecureClientRejected(t *testing.T) {
	cfg := &Config{}
	cfg.Guardrail.Cascade.Unknown = CascadeBlock
	if err := cfg.ValidateCascade(false); err != nil {
		t.Fatalf("plain config: %v", err)
	}
}
