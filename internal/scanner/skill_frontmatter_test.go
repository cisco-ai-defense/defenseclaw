// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1671: the gateway scan also checks the SKILL.md frontmatter description,
// keeping only YARA findings from that pass.
func TestSkillScanner_ScansFrontmatterDescription(t *testing.T) {
	out := `{"findings":[` +
		`{"id":"y1","rule_id":"YARA_prompt_injection_generic","severity":"CRITICAL","title":"PROMPT INJECTION detected by YARA"},` +
		`{"id":"s1","rule_id":"SOCIAL_ENG_VAGUE_DESCRIPTION","severity":"LOW","title":"Vague skill description"}]}`
	bin := buildScannerFixture(t, out, 0)
	ss := NewSkillScanner(config.SkillScannerConfig{Binary: bin}, config.InspectLLMConfig{}, config.CiscoAIDefenseConfig{})

	skill := filepath.Join(t.TempDir(), "top")
	if err := os.MkdirAll(skill, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(manifest string) {
		if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte(manifest), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write("# no frontmatter\n")
	plain, err := ss.Scan(context.Background(), skill)
	if err != nil || len(plain.Findings) != 2 {
		t.Fatalf("plain scan = %+v, %v; want the 2 body findings", plain, err)
	}

	write("---\nname: top\ndescription: Marker description text.\n---\n\nBody.\n")
	result, err := ss.Scan(context.Background(), skill)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 3 {
		t.Fatalf("findings = %+v; want 2 body + 1 description YARA finding", result.Findings)
	}
	extra := result.Findings[2]
	if extra.RuleID != "YARA_prompt_injection_generic" || extra.Location != "SKILL.md (frontmatter description)" {
		t.Fatalf("description finding = %+v", extra)
	}
}

func TestSkillDescriptionParsesFrontmatter(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(manifest, []byte("---\r\nname: a\r\ndescription: >\r\n  two\r\n  lines\r\n---\r\nbody\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := skillDescription(dir); got != "two lines" {
		t.Fatalf("skillDescription(dir) = %q", got)
	}
	if got := skillDescription(manifest); got != "two lines" {
		t.Fatalf("skillDescription(file) = %q", got)
	}
	if got := skillDescription(filepath.Join(dir, "missing")); got != "" {
		t.Fatalf("missing = %q", got)
	}
}
