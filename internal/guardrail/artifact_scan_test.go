// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

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

// GAP-0364: cloning anthropics/skills quarantined claude-api for a CRITICAL
// CMD-RM-RF that joined "rm -rf /workspace/reports" in a JSON example to a
// "/" lines further down, and for COG-MEMORY on docs that explain MEMORY.md.
// Command rules now match within one line, and path-write rules skip
// documentation other than SKILL.md.
func TestArtifactRulesSkipDocMentionsAndCrossLineCommands(t *testing.T) {
	dir := t.TempDir()
	for name, text := range map[string]string{
		"SKILL.md":         "# notes\nWrite what you learn to MEMORY.md.\n",
		"shared/tools.md":  "```json\n{ \"input\": { \"command\": \"rm -rf /workspace/reports\" },\n  \"note\": \"paths under / are protected\" }\n```\n",
		"shared/memory.md": "The memory tool keeps notes in MEMORY.md.\n",
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
	findings, err := pack.ScanArtifact(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	for _, f := range findings {
		found[f.RuleID+" "+strings.SplitN(f.Location, ":", 2)[0]] = f.Location
	}
	if _, ok := found["CMD-RM-RF shared/tools.md"]; ok {
		t.Errorf("CMD-RM-RF matched across lines of a JSON example: %v", found)
	}
	if _, ok := found["COG-MEMORY shared/memory.md"]; ok {
		t.Errorf("COG-MEMORY fired on documentation: %v", found)
	}
	if _, ok := found["COG-MEMORY SKILL.md"]; !ok {
		t.Errorf("COG-MEMORY no longer checks SKILL.md: %v", found)
	}
	if got := scanArtifactText(pack.artifactRules(), "cleanup:\n\trm -rf /\n", "Makefile"); len(got) == 0 {
		t.Error("a one-line rm -rf / is no longer found")
	}
}

// A Python path match must reach a write call, including through a local
// target variable; a mere data-list mention is not a finding.
func TestArtifactPythonPathWriteNeedsWriteCall(t *testing.T) {
	pack := &RulePack{RuleFiles: []*RulesFileYAML{{
		Category: "cognitive-file",
		Rules: []RuleDefYAML{{
			ID: "COG-MEMORY", Pattern: `MEMORY\.md`, Title: "memory marker",
			Severity: "HIGH", Confidence: 0.9,
			Expression: "f.paths.exists(p, p.access == defenseclaw.guardrail.semantic.v1.PathAccess.PATH_ACCESS_WRITE)",
		}},
	}}}
	source := `from pathlib import Path
NEVER_TRACK = {"MEMORY.md"}
def save(note):
    target = Path.home() / "MEMORY.md"
    with open(target, "a") as fh:
        fh.write(note)
`
	found := scanArtifactText(pack.artifactRules(), source, "writer.py")
	if len(found) != 1 || found[0].Location != "writer.py:4" {
		t.Fatalf("Python write findings = %+v, want writer.py:4", found)
	}
	if mentions := scanArtifactText(pack.artifactRules(), `NEVER_TRACK = {"MEMORY.md"}`, "notes.py"); len(mentions) != 0 {
		t.Fatalf("data-list mention became a write: %+v", mentions)
	}
	if direct := scanArtifactText(pack.artifactRules(), `Path("MEMORY.md").write_text("note")`, "direct.py"); len(direct) != 1 {
		t.Fatalf("direct Python write findings = %+v, want one", direct)
	}
	if unrelated := scanArtifactText(pack.artifactRules(), `open(other, "w"); print("MEMORY.md")`, "unrelated.py"); len(unrelated) != 0 {
		t.Fatalf("unrelated write became a path write: %+v", unrelated)
	}
}

func TestArtifactOverlayScansUTF16SkillManifest(t *testing.T) {
	dir := t.TempDir()
	content := "# introduction\ndc-review-marker\n"
	encoded := []byte{0xFF, 0xFE}
	for _, unit := range utf16.Encode([]rune(content)) {
		encoded = append(encoded, byte(unit), byte(unit>>8))
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	pack := &RulePack{RuleFiles: []*RulesFileYAML{{
		Category: "command",
		Rules:    []RuleDefYAML{{ID: "T-MARKER", Pattern: "dc-review-marker", Severity: "HIGH"}},
	}}}
	result, err := NewArtifactOverlay(infoScanner{}, pack).Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range result.Findings {
		if finding.RuleID == "T-MARKER" && finding.Location == "SKILL.md:2" && finding.Severity == scanner.SeverityHigh {
			return
		}
	}
	t.Fatalf("UTF-16 SKILL.md rule-pack finding missing: %+v", result.Findings)
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
