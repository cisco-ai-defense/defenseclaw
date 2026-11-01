// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"gopkg.in/yaml.v3"
)

// GAP-1488: the config writer keeps the pre-1.0.4 default MCP compatibility
// only for what a write did not decide. Each admission block in the fixture is
// what the writer wrote for one write over the old default preset, by
// config_writer.apply (cases) or by a live policy edit or TUI Setup row that
// saves through Config.save (live_edits), or by a 1.0.4 command that chose
// the old preset's shape (chosen: policy activate of a named policy, a write
// that made the shape); cli/tests/test_config_writer.py checks that. The
// gateway compiles every decided MCP severity as written,
// never as warn.
func TestWritesOverTheLegacyDefaultCompileInGo(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/admission_legacy_default_writes.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Legacy json.RawMessage `json:"legacy"`
		Cases  []struct {
			Name      string            `json:"name"`
			Verdicts  map[string]string `json:"verdicts"`
			Admission json.RawMessage   `json:"admission"`
		} `json:"cases"`
		LiveEdits []struct {
			Name      string            `json:"name"`
			Verdicts  map[string]string `json:"verdicts"`
			Admission json.RawMessage   `json:"admission"`
		} `json:"live_edits"`
		Chosen []struct {
			Name      string            `json:"name"`
			Verdicts  map[string]string `json:"verdicts"`
			Admission json.RawMessage   `json:"admission"`
		} `json:"chosen"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	eng := repoEngine(t)
	check := func(name string, block json.RawMessage, want map[string]string) {
		t.Helper()
		var adm config.AdmissionConfig
		if err := yaml.Unmarshal(block, &adm); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		cfg := config.DefaultConfig()
		cfg.Admission = adm
		for severity, verdict := range want {
			in := AdmissionInput{
				TargetType: config.AdmissionTypeMCP, TargetName: "context7",
				ScanResult: &ScanResultInput{MaxSeverity: severity, TotalFindings: 1, ScannerName: "mcp-scanner"},
				Admission:  AdmissionFor(CompileAdmission(cfg), config.AdmissionTypeMCP),
			}
			fallback := EvaluateAdmissionFallback(in)
			rego, err := eng.Evaluate(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			if fallback.Verdict != verdict || rego.Verdict != verdict {
				t.Errorf("%s %s: fallback=%s rego=%s, want %s", name, severity, fallback.Verdict, rego.Verdict, verdict)
			}
		}
	}
	check("untouched legacy default", fixture.Legacy,
		map[string]string{"CRITICAL": "rejected", "HIGH": "warning", "MEDIUM": "warning", "LOW": "warning"})
	if len(fixture.Cases) == 0 || len(fixture.LiveEdits) == 0 || len(fixture.Chosen) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range fixture.Cases {
		check(c.Name, c.Admission, c.Verdicts)
	}
	for _, c := range fixture.LiveEdits {
		check(c.Name, c.Admission, c.Verdicts)
	}
	// Blocks a 1.0.4 command chose with the old preset's shape (policy
	// activate of a named policy, a write that made the shape) compile as
	// written: MCP HIGH, MEDIUM and LOW are refused.
	for _, c := range fixture.Chosen {
		check(c.Name, c.Admission, c.Verdicts)
	}
}
