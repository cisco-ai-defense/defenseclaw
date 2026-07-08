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

package guardrail

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validManagedRuleFile = `version: 1
category: agent-control
rules:
  - id: AC-CMD-RM-RF
    pattern: '(?i)rm\s+-rf'
    title: Recursive deletion
    severity: HIGH
    confidence: 0.99
    tags: [filesystem]
`

func writeOverlay(t *testing.T, filename, contents string) string {
	t.Helper()
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	if err := os.Mkdir(rulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if filename != "" {
		if err := os.WriteFile(filepath.Join(rulesDir, filename), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLoadRulePackWithOverlaysPreservesBaseAndAddsRules(t *testing.T) {
	overlay := writeOverlay(t, "agent-control.yaml", validManagedRuleFile)
	rp, err := LoadRulePackWithOverlays("", []string{overlay})
	if err != nil {
		t.Fatal(err)
	}
	if rp.Suppressions == nil || len(rp.JudgeConfigs) == 0 || rp.SensitiveTools == nil {
		t.Fatal("managed overlay discarded embedded base pack content")
	}
	if len(rp.RuleFiles) == 0 {
		t.Fatal("managed rule file was not appended")
	}
	last := rp.RuleFiles[len(rp.RuleFiles)-1]
	if last.Category != "agent-control" || len(last.Rules) != 1 || last.Rules[0].ID != "AC-CMD-RM-RF" {
		t.Fatalf("unexpected managed rules: %+v", last)
	}
}

func TestLoadRulePackWithOverlaysAppliesAfterEachConnectorBase(t *testing.T) {
	writeBase := func(category, ruleID string) string {
		t.Helper()
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "rules"), 0o700); err != nil {
			t.Fatal(err)
		}
		contents := strings.NewReplacer(
			"category: agent-control", "category: "+category,
			"AC-CMD-RM-RF", ruleID,
		).Replace(validManagedRuleFile)
		if err := os.WriteFile(filepath.Join(dir, "rules", category+".yaml"), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	overlay := writeOverlay(t, "agent-control.yaml", validManagedRuleFile)
	for _, test := range []struct {
		category string
		ruleID   string
	}{
		{category: "connector-one", ruleID: "BASE-ONE"},
		{category: "connector-two", ruleID: "BASE-TWO"},
	} {
		rp, err := LoadRulePackWithOverlays(writeBase(test.category, test.ruleID), []string{overlay})
		if err != nil {
			t.Fatal(err)
		}
		categories := make(map[string]bool)
		for _, file := range rp.RuleFiles {
			categories[file.Category] = true
		}
		if !categories[test.category] || !categories["agent-control"] {
			t.Fatalf("base %q and managed category not both present: %#v", test.category, categories)
		}
	}
}

func TestLoadRulePackWithEmptyOverlayPreservesBase(t *testing.T) {
	overlay := writeOverlay(t, "", "")
	base := LoadRulePack("")
	rp, err := LoadRulePackWithOverlays("", []string{overlay})
	if err != nil {
		t.Fatal(err)
	}
	if len(rp.RuleFiles) != len(base.RuleFiles) {
		t.Fatalf("rule file count = %d, want %d", len(rp.RuleFiles), len(base.RuleFiles))
	}
}

func TestLoadRulePackWithOverlaysRejectsInvalidManagedRules(t *testing.T) {
	tests := map[string]string{
		"unknown field":  strings.Replace(validManagedRuleFile, "version: 1", "version: 1\nunknown: true", 1),
		"bad version":    strings.Replace(validManagedRuleFile, "version: 1", "version: 2", 1),
		"empty rules":    "version: 1\ncategory: agent-control\nrules: []\n",
		"bad regex":      strings.Replace(validManagedRuleFile, "'(?i)rm\\s+-rf'", "'['", 1),
		"none severity":  strings.Replace(validManagedRuleFile, "severity: HIGH", "severity: NONE", 1),
		"bad confidence": strings.Replace(validManagedRuleFile, "confidence: 0.99", "confidence: 1.1", 1),
		"empty tag":      strings.Replace(validManagedRuleFile, "tags: [filesystem]", "tags: ['']", 1),
	}
	for name, contents := range tests {
		t.Run(name, func(t *testing.T) {
			overlay := writeOverlay(t, "agent-control.yaml", contents)
			if _, err := LoadRulePackWithOverlays("", []string{overlay}); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestLoadRulePackWithOverlaysRejectsDuplicateRuleIDs(t *testing.T) {
	overlay := writeOverlay(t, "agent-control.yaml", validManagedRuleFile)
	second := strings.Replace(validManagedRuleFile, "category: agent-control", "category: other", 1)
	second = strings.Replace(second, "Recursive deletion", "Different title", 1)
	if err := os.WriteFile(filepath.Join(overlay, "rules", "other.yaml"), []byte(second), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRulePackWithOverlays("", []string{overlay}); err == nil || !strings.Contains(err.Error(), "duplicate rule id") {
		t.Fatalf("expected duplicate rule id error, got %v", err)
	}
}

func TestLoadRulePackWithOverlaysRejectsRuleIDFromBase(t *testing.T) {
	base := writeOverlay(t, "base.yaml", strings.Replace(validManagedRuleFile, "category: agent-control", "category: base", 1))
	overlay := writeOverlay(t, "agent-control.yaml", validManagedRuleFile)
	if _, err := LoadRulePackWithOverlays(base, []string{overlay}); err == nil ||
		!strings.Contains(err.Error(), "duplicate rule id") {
		t.Fatalf("expected base/overlay duplicate rule id error, got %v", err)
	}
}

func TestLoadRulePackWithOverlaysRejectsUnexpectedRootEntry(t *testing.T) {
	overlay := writeOverlay(t, "agent-control.yaml", validManagedRuleFile)
	if err := os.WriteFile(filepath.Join(overlay, "suppressions.yaml"), []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRulePackWithOverlays("", []string{overlay}); err == nil {
		t.Fatal("expected rules-only overlay error")
	}
}

func TestLoadRulePackWithOverlaysRejectsHardLinkedManagedFile(t *testing.T) {
	overlay := writeOverlay(t, "agent-control.yaml", validManagedRuleFile)
	path := filepath.Join(overlay, "rules", "agent-control.yaml")
	if err := os.Link(path, filepath.Join(overlay, "rules", "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRulePackWithOverlays("", []string{overlay}); err == nil || !strings.Contains(err.Error(), "hard links") {
		t.Fatalf("expected hard-link rejection, got %v", err)
	}
}

func TestLoadRulePackWithOverlaysReservesAgentControlFilenameAndCategory(t *testing.T) {
	tests := map[string]struct {
		filename string
		content  string
	}{
		"reserved category in another file": {
			filename: "other.yaml",
			content:  validManagedRuleFile,
		},
		"reserved filename with another category": {
			filename: "agent-control.yaml",
			content:  strings.Replace(validManagedRuleFile, "category: agent-control", "category: other", 1),
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			overlay := writeOverlay(t, test.filename, test.content)
			if _, err := LoadRulePackWithOverlays("", []string{overlay}); err == nil {
				t.Fatal("expected reserved Agent Control category error")
			}
		})
	}
}

func TestLoadRulePackWithOverlaysRejectsMultipleAgentControlCategories(t *testing.T) {
	first := writeOverlay(t, "agent-control.yaml", validManagedRuleFile)
	secondContents := strings.Replace(validManagedRuleFile, "AC-CMD-RM-RF", "AC-OTHER", 1)
	second := writeOverlay(t, "agent-control.yaml", secondContents)
	if _, err := LoadRulePackWithOverlays("", []string{first, second}); err == nil ||
		!strings.Contains(err.Error(), "only once") {
		t.Fatalf("expected reserved category duplication error, got %v", err)
	}
}

func TestAgentControlRulePackStatusUsesExactBytes(t *testing.T) {
	overlay := writeOverlay(t, "agent-control.yaml", validManagedRuleFile)
	status, err := AgentControlRulePackStatus([]string{overlay})
	if err != nil {
		t.Fatal(err)
	}
	if !status.Present {
		t.Fatal("expected present status")
	}
	sum := sha256.Sum256([]byte(validManagedRuleFile))
	want := "sha256:" + hex.EncodeToString(sum[:])
	if status.ArtifactDigest != want {
		t.Fatalf("digest = %q, want %q", status.ArtifactDigest, want)
	}
}

func TestAgentControlRulePackStatusRejectsMultipleArtifacts(t *testing.T) {
	first := writeOverlay(t, "agent-control.yaml", validManagedRuleFile)
	second := writeOverlay(t, "agent-control.yaml", validManagedRuleFile)
	if _, err := AgentControlRulePackStatus([]string{first, second}); err == nil ||
		!strings.Contains(err.Error(), "only once") {
		t.Fatalf("expected duplicate Agent Control artifact error, got %v", err)
	}
}
