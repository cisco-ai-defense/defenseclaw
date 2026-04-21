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

package scanner

import (
	"context"
	"os"
	"os/exec"
	"testing"
)

// TestParsePluginOutput_RealFormat verifies that parsePluginOutput correctly
// handles the JSON output from the Python plugin scanner CLI
// (defenseclaw plugin scan --json).
func TestParsePluginOutput_RealFormat(t *testing.T) {
	raw := []byte(`{
		"scanner": "plugin-scanner",
		"target": "/tmp/test-plugin",
		"timestamp": "2026-03-24T12:00:00.000Z",
		"findings": [
			{
				"id": "plugin-1",
				"rule_id": "PERM-DANGEROUS",
				"severity": "HIGH",
				"confidence": 0.9,
				"title": "Dangerous permission: fs:*",
				"description": "Plugin requests broad filesystem access",
				"evidence": "\"permissions\": [\"fs:*\"]",
				"location": "package.json",
				"remediation": "Request specific file paths instead of fs:*",
				"scanner": "plugin-scanner",
				"tags": ["permissions"],
				"taxonomy": {"objective": "OB-009", "technique": "AITech-9.1"},
				"occurrence_count": 1,
				"suppressed": false
			},
			{
				"id": "plugin-2",
				"rule_id": "SRC-EVAL",
				"severity": "CRITICAL",
				"confidence": 0.95,
				"title": "Dynamic code execution via eval()",
				"description": "eval() can execute arbitrary code",
				"evidence": "eval(userInput)",
				"location": "src/index.ts:42",
				"remediation": "Remove eval() usage",
				"scanner": "plugin-scanner",
				"tags": ["code-execution"],
				"taxonomy": {"objective": "OB-005", "technique": "AITech-5.1"},
				"occurrence_count": 1,
				"suppressed": false
			},
			{
				"id": "plugin-3",
				"rule_id": "SRC-CRED",
				"severity": "MEDIUM",
				"confidence": 0.7,
				"title": "Possible credential access",
				"description": "Reads credential files",
				"location": "src/helper.ts:10",
				"scanner": "plugin-scanner",
				"tags": ["credential-theft"],
				"occurrence_count": 1,
				"suppressed": true,
				"suppression_reason": "false positive"
			}
		],
		"duration_ns": 150000000,
		"metadata": {
			"manifest_name": "test-plugin",
			"manifest_version": "1.0.0",
			"file_count": 5,
			"total_size_bytes": 12345,
			"has_lockfile": true,
			"has_install_scripts": false,
			"detected_capabilities": ["eval", "fs"]
		},
		"assessment": {
			"verdict": "malicious",
			"confidence": 0.95,
			"summary": "Plugin has 1 critical finding(s).",
			"categories": []
		}
	}`)

	findings, err := parsePluginOutput(raw)
	if err != nil {
		t.Fatalf("parsePluginOutput: %v", err)
	}

	// Should have 2 findings (3rd is suppressed)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (1 suppressed), got %d", len(findings))
	}

	// Verify first finding
	if findings[0].ID != "plugin-1" {
		t.Errorf("finding[0].ID = %q, want plugin-1", findings[0].ID)
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("finding[0].Severity = %q, want HIGH", findings[0].Severity)
	}
	if findings[0].Title != "Dangerous permission: fs:*" {
		t.Errorf("finding[0].Title = %q", findings[0].Title)
	}
	if findings[0].Location != "package.json" {
		t.Errorf("finding[0].Location = %q, want package.json", findings[0].Location)
	}
	if len(findings[0].Tags) != 1 || findings[0].Tags[0] != "permissions" {
		t.Errorf("finding[0].Tags = %v, want [permissions]", findings[0].Tags)
	}

	// Verify second finding (CRITICAL)
	if findings[1].Severity != SeverityCritical {
		t.Errorf("finding[1].Severity = %q, want CRITICAL", findings[1].Severity)
	}

	// Verify MaxSeverity works with parsed findings
	result := &ScanResult{Findings: findings}
	if result.MaxSeverity() != SeverityCritical {
		t.Errorf("MaxSeverity = %q, want CRITICAL", result.MaxSeverity())
	}
	if result.IsClean() {
		t.Error("expected not clean")
	}
}

func TestParsePluginOutput_EmptyFindings(t *testing.T) {
	raw := []byte(`{
		"scanner": "plugin-scanner",
		"target": "/tmp/clean-plugin",
		"timestamp": "2026-03-24T12:00:00.000Z",
		"findings": [],
		"duration_ns": 50000000,
		"assessment": {
			"verdict": "benign",
			"confidence": 0.9,
			"summary": "No security issues detected.",
			"categories": []
		}
	}`)

	findings, err := parsePluginOutput(raw)
	if err != nil {
		t.Fatalf("parsePluginOutput: %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}

	result := &ScanResult{Findings: findings}
	if !result.IsClean() {
		t.Error("expected clean scan")
	}
}

// TestPluginScanner_Integration calls the real Python CLI and verifies
// Go can parse its output end-to-end. Skipped if defenseclaw is not installed.
func TestPluginScanner_Integration(t *testing.T) {
	binary := "defenseclaw"
	if envBin := os.Getenv("DEFENSECLAW_BIN"); envBin != "" {
		binary = envBin
	}
	if _, err := exec.LookPath(binary); err != nil {
		t.Skipf("skipping: %s not in PATH", binary)
	}

	scanner := NewPluginScanner(binary)

	// Scan this repo's extensions/defenseclaw directory as a real target
	target := "../../extensions/defenseclaw"
	if _, err := os.Stat(target); err != nil {
		t.Skipf("skipping: target %s not found", target)
	}

	result, err := scanner.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if result.Scanner != "plugin-scanner" {
		t.Errorf("Scanner = %q, want plugin-scanner", result.Scanner)
	}
	if result.Target != target {
		t.Errorf("Target = %q, want %q", result.Target, target)
	}
	// The extension has real findings (child_process import, localhost refs, etc.)
	if len(result.Findings) == 0 {
		t.Error("expected at least 1 finding from scanning extensions/defenseclaw")
	}
	for i, f := range result.Findings {
		if f.ID == "" {
			t.Errorf("finding[%d].ID is empty", i)
		}
		if f.Severity == "" {
			t.Errorf("finding[%d].Severity is empty", i)
		}
		if f.Title == "" {
			t.Errorf("finding[%d].Title is empty", i)
		}
	}

	t.Logf("OK: %d findings, max severity = %s", len(result.Findings), result.MaxSeverity())
}

func TestParsePluginOutput_AllSuppressed(t *testing.T) {
	raw := []byte(`{
		"scanner": "plugin-scanner",
		"target": "/tmp/suppressed-plugin",
		"timestamp": "2026-03-24T12:00:00.000Z",
		"findings": [
			{
				"id": "plugin-1",
				"severity": "HIGH",
				"title": "False positive",
				"description": "Not a real issue",
				"scanner": "plugin-scanner",
				"suppressed": true,
				"suppression_reason": "known safe"
			}
		]
	}`)

	findings, err := parsePluginOutput(raw)
	if err != nil {
		t.Fatalf("parsePluginOutput: %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings (all suppressed), got %d", len(findings))
	}
}

func TestPluginScanCommand(t *testing.T) {
	t.Run("default cli path uses plugin subcommand", func(t *testing.T) {
		s := &PluginScanner{BinaryPath: ""}
		binary, args := s.pluginScanCommand("/tmp/plugin")
		if binary != "defenseclaw" {
			t.Fatalf("binary = %q, want defenseclaw", binary)
		}
		want := []string{"plugin", "scan", "--json", "/tmp/plugin"}
		if len(args) != len(want) {
			t.Fatalf("len(args) = %d, want %d (%v)", len(args), len(want), args)
		}
		for i := range want {
			if args[i] != want[i] {
				t.Fatalf("args[%d] = %q, want %q", i, args[i], want[i])
			}
		}
	})

	t.Run("legacy standalone scanner remains supported", func(t *testing.T) {
		s := &PluginScanner{BinaryPath: "/usr/local/bin/defenseclaw-plugin-scanner"}
		binary, args := s.pluginScanCommand("/tmp/plugin")
		if binary != "/usr/local/bin/defenseclaw-plugin-scanner" {
			t.Fatalf("binary = %q", binary)
		}
		if len(args) != 1 || args[0] != "/tmp/plugin" {
			t.Fatalf("args = %v, want [/tmp/plugin]", args)
		}
	})

	t.Run("policy and profile flags are appended", func(t *testing.T) {
		s := &PluginScanner{BinaryPath: "defenseclaw", Policy: "strict", Profile: "enterprise"}
		_, args := s.pluginScanCommand("/tmp/plugin")
		want := []string{"plugin", "scan", "--json", "/tmp/plugin", "--policy", "strict", "--profile", "enterprise"}
		if len(args) != len(want) {
			t.Fatalf("len(args) = %d, want %d (%v)", len(args), len(want), args)
		}
		for i := range want {
			if args[i] != want[i] {
				t.Fatalf("args[%d] = %q, want %q", i, args[i], want[i])
			}
		}
	})
}
