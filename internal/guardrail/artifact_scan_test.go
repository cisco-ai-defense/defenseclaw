// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

type infoScanner struct{}

func (infoScanner) Name() string               { return "skill-scanner" }
func (infoScanner) Version() string            { return "test" }
func (infoScanner) SupportedTargets() []string { return []string{"skill"} }
func (infoScanner) Scan(_ context.Context, target string) (*scanner.ScanResult, error) {
	return &scanner.ScanResult{
		Scanner: "skill-scanner", Target: target,
		Findings: []scanner.Finding{{ID: "SKILL-INFO", Severity: scanner.SeverityInfo, Location: "SKILL.md"}},
	}, nil
}

// A skill with an AWS example key in a script is CRITICAL for the install
// watcher too, not only for `defenseclaw skill scan` (GAP-0065).
func TestArtifactOverlayAddsTheRulePackFindingsToASkillScan(t *testing.T) {
	const key = `KEY = "AKIAIOSFODNN7EXAMPLE"` + "\n"
	dir := t.TempDir()
	for name, text := range map[string]string{
		"SKILL.md":                  "# a skill\n",
		"scripts/cfg.py":            "import os\n" + key,
		"node_modules/dep/index.js": key,
		"logo.png":                  key,
	} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pack := mustLoadRulePack(t, filepath.Join("..", "..", "policies", "guardrail", "default"))

	result, err := NewArtifactOverlay(infoScanner{}, pack).Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := result.MaxSeverity(); got != scanner.SeverityCritical {
		t.Fatalf("max severity = %s, want CRITICAL: %+v", got, result.Findings)
	}
	var aws []scanner.Finding
	for _, f := range result.Findings {
		if f.ID == "SEC-AWS-KEY" {
			aws = append(aws, f)
		}
	}
	if len(aws) != 1 || aws[0].Location != filepath.Join("scripts", "cfg.py")+":2" || aws[0].Scanner != "skill-scanner" {
		t.Fatalf("SEC-AWS-KEY findings = %+v, want one at scripts/cfg.py:2 (vendored and binary files are skipped)", aws)
	}

	// Rules that are off, for tool calls only, or about data in traffic do not
	// describe files.
	off := false
	narrow := &RulePack{RuleFiles: []*RulesFileYAML{
		{Category: "secret", Rules: []RuleDefYAML{
			{ID: "OFF", Pattern: `AKIA`, Severity: "HIGH", Enabled: &off},
			{ID: "TOOL", Pattern: `AKIA`, Severity: "HIGH", ToolCallOnly: true},
		}},
		{Category: "enterprise-data", Rules: []RuleDefYAML{{ID: "DATA", Pattern: `AKIA`, Severity: "HIGH"}}},
	}}
	if findings, err := narrow.ScanArtifact(context.Background(), dir); err != nil || len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}

func TestArtifactOverlayRejectsCanceledTraversal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("benign"), 0o600); err != nil {
		t.Fatal(err)
	}
	pack := &RulePack{RuleFiles: []*RulesFileYAML{{Category: "test", Rules: []RuleDefYAML{{ID: "MARKER", Pattern: "marker", Severity: "HIGH"}}}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewArtifactOverlay(infoScanner{}, pack).Scan(ctx, dir); !errors.Is(err, context.Canceled) {
		t.Fatalf("scan error = %v, want context cancellation", err)
	}
}

func TestArtifactOverlayRejectsFileCap(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i <= artifactMaxFiles; i++ {
		name := filepath.Join(dir, fmt.Sprintf("%04d.txt", i))
		if err := os.WriteFile(name, []byte("benign"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pack := &RulePack{RuleFiles: []*RulesFileYAML{{Category: "test", Rules: []RuleDefYAML{{ID: "MARKER", Pattern: "marker", Severity: "HIGH"}}}}}
	if _, err := NewArtifactOverlay(infoScanner{}, pack).Scan(context.Background(), dir); err == nil {
		t.Fatal("scan of more than 2000 readable files succeeded with incomplete coverage")
	}
}
