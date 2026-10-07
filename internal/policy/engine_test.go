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

package policy

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// repoRegoDir is the shipped policies/rego directory.
func repoRegoDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(thisFile), "..", "..", "policies", "rego")
	if _, err := os.Stat(filepath.Join(dir, "admission.rego")); err != nil {
		t.Skipf("policies/rego not found at %s", dir)
	}
	return dir
}

func repoEngine(t *testing.T) *Engine {
	t.Helper()
	eng, err := NewExact(repoRegoDir(t))
	if err != nil {
		t.Fatalf("NewExact: %v", err)
	}
	return eng
}

// TestAdmissionRegoAndFallbackAgree pins admission.rego and
// EvaluateAdmissionFallback to the same decision for the compiled built-in
// admission, so an OPA outage never changes an admission outcome.
func TestAdmissionRegoAndFallbackAgree(t *testing.T) {
	eng := repoEngine(t)
	compiled := CompileAdmission(config.DefaultConfig())
	noScanOnInstall := CompileAdmission(&config.Config{Admission: config.AdmissionConfig{
		MCP: config.AdmissionAssetType{ScanOnInstall: boolPtr(false)},
	}})
	allowLow := CompileAdmission(&config.Config{Admission: config.AdmissionConfig{
		Skill: config.AdmissionAssetType{
			Actions:          config.AdmissionActionMap{Low: &config.AdmissionAction{Shorthand: config.AdmissionActionAllow}},
			ScannerOverrides: map[string]config.AdmissionActionMap{"virustotal": {Medium: &config.AdmissionAction{Shorthand: config.AdmissionActionBlock}}},
		},
	}})
	scan := func(sev string, n int, scanner string) *ScanResultInput {
		return &ScanResultInput{MaxSeverity: sev, TotalFindings: n, ScannerName: scanner}
	}
	entry := func(name, path string) []ListEntry {
		return []ListEntry{{TargetType: "skill", TargetName: name, Reason: "operator", SourcePath: path}}
	}
	cases := []struct {
		name      string
		in        AdmissionInput
		admission map[string]CompiledAdmission
		verdict   string
	}{
		{name: "pre-scan", in: AdmissionInput{TargetType: "skill", TargetName: "s"}, verdict: "scan"},
		{name: "blocked", in: AdmissionInput{TargetType: "skill", TargetName: "s", BlockList: entry("s", "")}, verdict: "blocked"},
		{name: "allow pinned match", in: AdmissionInput{TargetType: "skill", TargetName: "s", Path: "/opt/v/s", AllowList: entry("s", "/opt/v/s"), ScanResult: scan("HIGH", 1, "")}, verdict: "allowed"},
		{name: "allow pinned mismatch", in: AdmissionInput{TargetType: "skill", TargetName: "s", Path: "/tmp/s", AllowList: entry("s", "/opt/v/s")}, verdict: "scan"},
		{name: "first party", in: AdmissionInput{TargetType: "plugin", TargetName: "defenseclaw", Path: "/h/.claude/extensions/defenseclaw"}, verdict: "allowed"},
		{name: "first party lookalike", in: AdmissionInput{TargetType: "plugin", TargetName: "defenseclaw", Path: "/h/.claude/extensions/defenseclaw-evil"}, verdict: "scan"},
		{name: "scan on install off", in: AdmissionInput{TargetType: "mcp", TargetName: "m"}, admission: noScanOnInstall, verdict: "allowed"},
		{name: "clean", in: AdmissionInput{TargetType: "skill", TargetName: "s", ScanResult: scan("INFO", 0, "")}, verdict: "clean"},
		{name: "skill high", in: AdmissionInput{TargetType: "skill", TargetName: "s", ScanResult: scan("high", 2, "skill-scanner")}, verdict: "rejected"},
		{name: "skill medium", in: AdmissionInput{TargetType: "skill", TargetName: "s", ScanResult: scan("MEDIUM", 1, "skill-scanner")}, verdict: "warning"},
		{name: "mcp medium", in: AdmissionInput{TargetType: "mcp", TargetName: "m", ScanResult: scan("MEDIUM", 1, "")}, verdict: "rejected"},
		{name: "mcp low runtime block", in: AdmissionInput{TargetType: "mcp", TargetName: "m", ScanResult: scan("LOW", 1, "")}, verdict: "rejected"},
		{name: "plugin high", in: AdmissionInput{TargetType: "plugin", TargetName: "p", ScanResult: scan("HIGH", 1, "")}, verdict: "rejected"},
		{name: "allow shorthand", in: AdmissionInput{TargetType: "skill", TargetName: "s", ScanResult: scan("LOW", 1, "")}, admission: allowLow, verdict: "allowed"},
		{name: "scanner override", in: AdmissionInput{TargetType: "skill", TargetName: "s", ScanResult: scan("MEDIUM", 1, "virustotal")}, admission: allowLow, verdict: "rejected"},
		{name: "unknown severity", in: AdmissionInput{TargetType: "skill", TargetName: "s", ScanResult: scan("BOGUS", 1, "")}, verdict: "rejected"},
		{name: "scan exit code", in: AdmissionInput{TargetType: "plugin", TargetName: "p", ScanResult: &ScanResultInput{MaxSeverity: "INFO", ExitCode: 7}}, verdict: "rejected"},
		{name: "scan error", in: AdmissionInput{TargetType: "plugin", TargetName: "p", ScanResult: &ScanResultInput{MaxSeverity: "INFO", ScanError: "boom"}}, verdict: "rejected"},
		{name: "no admission fails closed", in: AdmissionInput{TargetType: "tool", TargetName: "t", ScanResult: scan("LOW", 1, "")}, admission: map[string]CompiledAdmission{}, verdict: "rejected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			adm := tc.admission
			if adm == nil {
				adm = compiled
			}
			in := tc.in
			in.Admission = AdmissionFor(adm, in.TargetType)
			opa, err := eng.Evaluate(context.Background(), in)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if opa.Verdict != tc.verdict {
				t.Fatalf("rego verdict = %q (%s), want %q", opa.Verdict, opa.Reason, tc.verdict)
			}
			if fallback := EvaluateAdmissionFallback(in); !reflect.DeepEqual(fallback, opa) {
				t.Fatalf("fallback = %+v, rego = %+v", fallback, opa)
			}
		})
	}
}

// TestCompileAdmissionLayers pins the resolution order: the type's own
// value, then (skill) the scanner gate, then admission.defaults, then the
// built-in default; and an empty first_party_allow_list clears the list.
// The gate applies with its shown defaults (HIGH, review MEDIUM) when the
// scanner keys are unset.
func TestCompileAdmissionLayers(t *testing.T) {
	block := &config.AdmissionAction{Shorthand: config.AdmissionActionBlock}
	cfg := config.DefaultConfig()
	cfg.Admission = config.AdmissionConfig{
		Defaults: config.AdmissionAssetType{Actions: config.AdmissionActionMap{Low: block}},
		Skill:    config.AdmissionAssetType{Actions: config.AdmissionActionMap{Critical: block}},
		Plugin:   config.AdmissionAssetType{FirstPartyAllowList: []config.AdmissionFirstParty{}},
	}
	got := CompileAdmission(cfg)

	skill := got[config.AdmissionTypeSkill]
	want := map[string]CompiledAction{
		"CRITICAL": {Install: "block", File: "none", Runtime: "block"},
		"HIGH":     actionQuarantine,
		"MEDIUM":   actionWarn,
		"LOW":      actionAllow,
		"INFO":     actionAllow,
	}
	if !reflect.DeepEqual(skill.Actions, want) || skill.Source != "config:admission.skill.actions" {
		t.Fatalf("skill = %+v (%s)", skill.Actions, skill.Source)
	}
	if mcp := got[config.AdmissionTypeMCP]; mcp.Actions["LOW"] != want["CRITICAL"] || mcp.Actions["MEDIUM"] != actionQuarantine {
		t.Fatalf("mcp = %+v", mcp.Actions)
	}
	if plugin := got[config.AdmissionTypePlugin]; plugin.FirstPartyAllowList == nil || len(plugin.FirstPartyAllowList) != 0 {
		t.Fatalf("plugin first party = %#v, want an empty list", plugin.FirstPartyAllowList)
	}
	if len(got[config.AdmissionTypeSkill].FirstPartyAllowList) != 1 {
		t.Fatalf("skill keeps the built-in codeguard entry: %#v", got[config.AdmissionTypeSkill].FirstPartyAllowList)
	}
}

func TestEvaluateGuardrailThresholdsAndHILT(t *testing.T) {
	eng := repoEngine(t)
	high := &GuardrailScanResult{Action: "block", Severity: "HIGH", Findings: []string{"marker"}, Reason: "marker"}
	cases := []struct {
		name string
		in   GuardrailInput
		want string
	}{
		{name: "default thresholds alert on high", in: GuardrailInput{Mode: "action", LocalResult: high}, want: "alert"},
		{name: "block at high", in: GuardrailInput{Mode: "action", LocalResult: high, Thresholds: &ThresholdsInput{Block: 3, Alert: 2, CiscoTrustLevel: "full"}}, want: "block"},
		{name: "hilt confirms", in: GuardrailInput{Mode: "action", LocalResult: high, HILT: &GuardrailHILTInput{Enabled: true, MinSeverity: "HIGH"}}, want: "confirm"},
	}
	for _, tc := range cases {
		out, err := eng.EvaluateGuardrail(context.Background(), tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if out.Action != tc.want {
			t.Fatalf("%s: action = %q, want %q", tc.name, out.Action, tc.want)
		}
	}
}

func boolPtr(v bool) *bool { return &v }

// TestPrepareRefusesPre9Modules: a 1.0 admission or guardrail module reads
// data.json documents that no longer exist and would fail open, so the load
// fails and the gateway uses the config-driven fallback.
func TestPrepareRefusesPre9Modules(t *testing.T) {
	dir := t.TempDir()
	stale := "package defenseclaw.guardrail\n\nimport rego.v1\n\naction := \"block\" if input.severity_rank >= data.guardrail.block_threshold\n"
	if err := os.WriteFile(filepath.Join(dir, "guardrail.rego"), []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(context.Background(), dir); err == nil {
		t.Fatal("Prepare accepted a module that reads data.guardrail")
	}
}

// TestSecureClientGuardrailThresholdsKeepTheDataJSON: the Secure Client
// /v1/guardrail/evaluate levels are the 1.0 data.json ones.
func TestSecureClientGuardrailThresholdsKeepTheDataJSON(t *testing.T) {
	policyDir := t.TempDir()
	if got := SecureClientGuardrailThresholds(policyDir); got != (ThresholdsInput{Block: 4, Alert: 2, CiscoTrustLevel: "full"}) {
		t.Fatalf("without data.json = %+v", got)
	}
	data := `{"guardrail": {"block_threshold": 3, "alert_threshold": 1, "cisco_trust_level": "advisory"}}`
	if err := os.WriteFile(filepath.Join(policyDir, "data.json"), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := SecureClientGuardrailThresholds(policyDir); got != (ThresholdsInput{Block: 3, Alert: 1, CiscoTrustLevel: "advisory"}) {
		t.Fatalf("with data.json = %+v", got)
	}
}

// TestSecureClientAdmissionKeepsTheDataJSON: a Secure Client config stays
// config_version 8, so its admission is the 1.0 one: <policy_dir>/rego/
// data.json over the shipped defaults, a finding below the block level is a
// warning (no scanner-gate "allowed"), and a tightened data.json applies.
func TestSecureClientAdmissionKeepsTheDataJSON(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	eng := repoEngine(t)
	policyDir := t.TempDir()
	cfg := &config.Config{DeploymentMode: "managed_enterprise", PolicyDir: policyDir}
	cfg.Enterprise.Profile = "secure_client"
	if !cfg.SecureClientIntegration() {
		t.Fatal("test config is not Secure Client")
	}
	verdict := func(sev string) string {
		in := AdmissionInput{TargetType: "skill", TargetName: "s", Path: "/x/s",
			ScanResult: &ScanResultInput{MaxSeverity: sev, TotalFindings: 1, ScannerName: "skill-scanner"}}
		in.Admission = AdmissionFor(CompileAdmission(cfg), "skill")
		out, err := eng.Evaluate(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		return out.Verdict
	}
	if got := verdict("LOW"); got != "warning" {
		t.Fatalf("LOW without data.json = %q, want warning", got)
	}
	if err := os.MkdirAll(filepath.Join(policyDir, "rego"), 0o700); err != nil {
		t.Fatal(err)
	}
	data := `{"actions": {"MEDIUM": {"install": "block", "file": "none", "runtime": "block"},
	  "LOW": {"install": "none", "file": "none", "runtime": "allow"}}}`
	if err := os.WriteFile(filepath.Join(policyDir, "rego", "data.json"), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := verdict("MEDIUM"); got != "rejected" {
		t.Fatalf("MEDIUM with a tightened data.json = %q, want rejected", got)
	}
}

// TestAssetPolicyListsForUseTheListResolver: a connector-scoped allow
// overrides a global deny for that connector in Rego and the fallback too,
// as config.AssetListDecision and the CLI decide.
func TestAssetPolicyListsForUseTheListResolver(t *testing.T) {
	eng := repoEngine(t)
	cfg := config.DefaultConfig()
	cfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{Name: "foo"}}
	cfg.AssetPolicy.Skill.Allowed = []config.AssetPolicyRule{{Name: "foo", Connector: "codex"}}
	for connector, want := range map[string]string{"codex": "allowed", "claudecode": "blocked"} {
		in := AdmissionInput{TargetType: "skill", TargetName: "foo", Path: "/home/u/.codex/skills/foo"}
		in.BlockList, in.AllowList = AssetPolicyListsFor(cfg, config.AssetPolicyInput{
			TargetType: "skill", Name: "foo", Connector: connector, SourcePath: in.Path,
		})
		in.Admission = AdmissionFor(CompileAdmission(cfg), "skill")
		opa, err := eng.Evaluate(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		if opa.Verdict != want || EvaluateAdmissionFallback(in).Verdict != want {
			t.Errorf("%s: rego %q fallback %q, want %q", connector, opa.Verdict, EvaluateAdmissionFallback(in).Verdict, want)
		}
	}
}
