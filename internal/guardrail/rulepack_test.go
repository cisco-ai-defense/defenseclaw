package guardrail

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRulePack_Embedded(t *testing.T) {
	rp := LoadRulePack("")
	if rp == nil {
		t.Fatal("LoadRulePack(\"\") returned nil")
	}
	if rp.Suppressions == nil {
		t.Fatal("Suppressions should be loaded from embedded defaults")
	}
	if len(rp.Suppressions.FindingSupps) == 0 {
		t.Error("expected at least one finding suppression in defaults")
	}
	if len(rp.Suppressions.PreJudgeStrips) == 0 {
		t.Error("expected at least one pre-judge strip in defaults")
	}
	if rp.SensitiveTools == nil {
		t.Fatal("SensitiveTools should be loaded from embedded defaults")
	}
	if len(rp.SensitiveTools.Tools) == 0 {
		t.Error("expected at least one sensitive tool in defaults")
	}
}

func TestLoadRulePack_JudgeConfigs(t *testing.T) {
	rp := LoadRulePack("")
	for _, name := range []string{"pii", "injection", "tool-injection"} {
		jc, ok := rp.JudgeConfigs[name]
		if !ok {
			t.Errorf("expected judge config for %q", name)
			continue
		}
		if jc.SystemPrompt == "" {
			t.Errorf("judge %q has empty system prompt", name)
		}
		if len(jc.Categories) == 0 {
			t.Errorf("judge %q has no categories", name)
		}
	}
}

func TestLoadRulePack_FromDisk(t *testing.T) {
	dir := t.TempDir()

	judgeDir := filepath.Join(dir, "judge")
	if err := os.MkdirAll(judgeDir, 0o755); err != nil {
		t.Fatal(err)
	}

	supYAML := `version: 1
pre_judge_strips: []
finding_suppressions:
  - id: TEST-SUPP
    finding_pattern: TEST-FINDING
    entity_pattern: '^test$'
    reason: "test suppression"
tool_suppressions: []
`
	if err := os.WriteFile(filepath.Join(dir, "suppressions.yaml"), []byte(supYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	rp := LoadRulePack(dir)
	if rp.Suppressions == nil {
		t.Fatal("Suppressions should be loaded from disk")
	}
	if len(rp.Suppressions.FindingSupps) != 1 || rp.Suppressions.FindingSupps[0].ID != "TEST-SUPP" {
		t.Errorf("expected TEST-SUPP suppression, got %+v", rp.Suppressions.FindingSupps)
	}
}

func TestLoadRulePack_CorruptFallback(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "suppressions.yaml"), []byte("{{invalid yaml"), 0o644); err != nil {
		t.Fatal(err)
	}

	rp := LoadRulePack(dir)
	if rp.Suppressions == nil {
		t.Fatal("corrupt YAML should fall back to embedded default")
	}
	if len(rp.Suppressions.FindingSupps) == 0 {
		t.Error("fallback should have finding suppressions")
	}
}

func TestLookupSensitiveTool(t *testing.T) {
	rp := LoadRulePack("")
	st := rp.LookupSensitiveTool("users_list")
	if st == nil {
		t.Fatal("expected to find users_list in sensitive tools")
	}
	if !st.ResultInspection {
		t.Error("users_list should have result_inspection=true")
	}
	if !st.JudgeResult {
		t.Error("users_list should have judge_result=true")
	}
	if st.MinEntitiesAlert != 3 {
		t.Errorf("users_list min_entities_for_alert = %d, want 3", st.MinEntitiesAlert)
	}

	if rp.LookupSensitiveTool("nonexistent_tool") != nil {
		t.Error("nonexistent tool should return nil")
	}
}

func TestRulePack_Nil(t *testing.T) {
	var rp *RulePack
	if rp.PIIJudge() != nil {
		t.Error("nil rulepack should return nil PIIJudge")
	}
	if rp.InjectionJudge() != nil {
		t.Error("nil rulepack should return nil InjectionJudge")
	}
	if rp.LookupSensitiveTool("x") != nil {
		t.Error("nil rulepack should return nil from LookupSensitiveTool")
	}
	rp.Validate()
	if s := rp.String(); s != "RulePack{nil}" {
		t.Errorf("nil rulepack String() = %q", s)
	}
}

func TestEffectiveSeverity(t *testing.T) {
	tests := []struct {
		name      string
		cat       JudgeCategory
		direction string
		fallback  string
		want      string
	}{
		{
			name:      "prompt with prompt severity",
			cat:       JudgeCategory{SeverityPrompt: "LOW", SeverityCompletion: "HIGH", SeverityDefault: "MEDIUM"},
			direction: "prompt",
			fallback:  "NONE",
			want:      "LOW",
		},
		{
			name:      "completion with completion severity",
			cat:       JudgeCategory{SeverityPrompt: "LOW", SeverityCompletion: "HIGH", SeverityDefault: "MEDIUM"},
			direction: "completion",
			fallback:  "NONE",
			want:      "HIGH",
		},
		{
			name:      "unknown direction uses default",
			cat:       JudgeCategory{SeverityDefault: "MEDIUM"},
			direction: "other",
			fallback:  "NONE",
			want:      "MEDIUM",
		},
		{
			name:      "severity field used",
			cat:       JudgeCategory{Severity: "HIGH"},
			direction: "prompt",
			fallback:  "NONE",
			want:      "HIGH",
		},
		{
			name:      "fallback used",
			cat:       JudgeCategory{},
			direction: "prompt",
			fallback:  "CRITICAL",
			want:      "CRITICAL",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.cat.EffectiveSeverity(tc.direction, tc.fallback)
			if got != tc.want {
				t.Errorf("EffectiveSeverity(%q, %q) = %q, want %q", tc.direction, tc.fallback, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// loadRuleFiles and RuleFiles on LoadRulePack
// ---------------------------------------------------------------------------

func TestLoadRuleFiles_FromDisk(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}

	yaml := `version: 1
category: custom-secret
direction: both
rules:
  - id: CUSTOM-SECRET-1
    pattern: "custom_key_[a-z0-9]{32}"
    severity: HIGH
    confidence: 0.9
    description: "Custom secret pattern"
`
	if err := os.WriteFile(filepath.Join(rulesDir, "custom.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	rp := LoadRulePack(dir)
	if rp == nil {
		t.Fatal("LoadRulePack returned nil")
	}
	if len(rp.RuleFiles) == 0 {
		t.Fatal("expected RuleFiles to contain the custom rule file")
	}

	found := false
	for _, rf := range rp.RuleFiles {
		if rf.Category == "custom-secret" {
			found = true
			if len(rf.Rules) != 1 {
				t.Errorf("expected 1 rule, got %d", len(rf.Rules))
			}
			if rf.Rules[0].ID != "CUSTOM-SECRET-1" {
				t.Errorf("rule ID = %s, want CUSTOM-SECRET-1", rf.Rules[0].ID)
			}
		}
	}
	if !found {
		t.Error("custom-secret category not found in RuleFiles")
	}
}

func TestLoadRuleFiles_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	rp := LoadRulePack(dir)
	if len(rp.RuleFiles) != 0 {
		t.Errorf("expected 0 rule files for empty dir, got %d", len(rp.RuleFiles))
	}
}

func TestLoadRuleFiles_BadVersion(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}

	yaml := `version: 99
category: future
rules: []
`
	if err := os.WriteFile(filepath.Join(rulesDir, "future.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	rp := LoadRulePack(dir)
	if len(rp.RuleFiles) != 0 {
		t.Errorf("version 99 should be skipped, got %d rule files", len(rp.RuleFiles))
	}
}

func TestLoadRuleFiles_CorruptYAML(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "bad.yaml"), []byte("{{{not yaml"), 0o644); err != nil {
		t.Fatal(err)
	}

	rp := LoadRulePack(dir)
	if len(rp.RuleFiles) != 0 {
		t.Errorf("corrupt YAML should be skipped, got %d rule files", len(rp.RuleFiles))
	}
}
