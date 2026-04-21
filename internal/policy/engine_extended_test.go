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
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func setupExtendedRegoDir(t *testing.T) string {
	t.Helper()

	_, thisFile, _, _ := runtime.Caller(0)
	srcRegoDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "policies", "rego")
	if _, err := os.Stat(srcRegoDir); err != nil {
		t.Skipf("policies/rego not found at %s — skipping", srcRegoDir)
	}

	dir := t.TempDir()

	// Copy all .rego files
	entries, err := os.ReadDir(srcRegoDir)
	if err != nil {
		t.Fatalf("read rego dir: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if filepath.Ext(name) != ".rego" {
			continue
		}
		// Skip test files
		if len(name) > 10 && name[len(name)-10:] == "_test.rego" {
			continue
		}
		src, _ := os.ReadFile(filepath.Join(srcRegoDir, name))
		os.WriteFile(filepath.Join(dir, name), src, 0644)
	}

	// Write controlled data.json (strict policy)
	data := map[string]interface{}{
		"config": map[string]interface{}{
			"policy_name":                   "strict",
			"allow_list_bypass_scan":        false,
			"scan_on_install":               true,
			"max_enforcement_delay_seconds": 1,
		},
		"actions": map[string]interface{}{
			"CRITICAL": map[string]string{"runtime": "block", "file": "quarantine", "install": "block"},
			"HIGH":     map[string]string{"runtime": "block", "file": "quarantine", "install": "block"},
			"MEDIUM":   map[string]string{"runtime": "block", "file": "quarantine", "install": "block"},
			"LOW":      map[string]string{"runtime": "allow", "file": "none", "install": "none"},
			"INFO":     map[string]string{"runtime": "allow", "file": "none", "install": "none"},
		},
		"scanner_overrides": map[string]interface{}{},
		"severity_ranking": map[string]int{
			"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1,
		},
		"audit": map[string]interface{}{
			"retention_days":   365,
			"log_all_actions":  true,
			"log_scan_results": true,
		},
		"firewall": map[string]interface{}{
			"default_action":       "deny",
			"blocked_destinations": []string{"169.254.169.254", "fd00:ec2::254"},
			"allowed_domains":      []string{"api.github.com", "github.com", "pypi.org"},
			"allowed_ports":        []int{443},
		},
		"sandbox": map[string]interface{}{
			"update_policy":           true,
			"default_permissions":     []string{},
			"denied_endpoints_global": []string{"169.254.169.254"},
		},
		"guardrail": map[string]interface{}{
			"severity_rank": map[string]int{
				"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
			},
			"block_threshold":   3,
			"alert_threshold":   2,
			"cisco_trust_level": "full",
			"patterns":          map[string]interface{}{},
			"severity_mappings": map[string]interface{}{},
		},
	}

	raw, _ := json.MarshalIndent(data, "", "  ")
	os.WriteFile(filepath.Join(dir, "data.json"), raw, 0644)

	return dir
}

func extEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := New(setupExtendedRegoDir(t))
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	return e
}

func extCtx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

// ---------------------------------------------------------------------------
// Firewall
// ---------------------------------------------------------------------------

func TestEngine_EvaluateFirewall_BlockedDest(t *testing.T) {
	e := extEngine(t)
	out, err := e.EvaluateFirewall(extCtx(t), FirewallInput{
		TargetType:  "skill",
		Destination: "169.254.169.254",
		Port:        80,
		Protocol:    "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != "deny" {
		t.Errorf("want deny for blocked dest, got %s", out.Action)
	}
}

func TestEngine_EvaluateFirewall_AllowedDomain(t *testing.T) {
	e := extEngine(t)
	out, err := e.EvaluateFirewall(extCtx(t), FirewallInput{
		TargetType:  "skill",
		Destination: "api.github.com",
		Port:        443,
		Protocol:    "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != "allow" {
		t.Errorf("want allow for github.com:443, got %s", out.Action)
	}
}

func TestEngine_EvaluateFirewall_UnknownDomain(t *testing.T) {
	e := extEngine(t)
	out, err := e.EvaluateFirewall(extCtx(t), FirewallInput{
		TargetType:  "skill",
		Destination: "evil.example.com",
		Port:        443,
		Protocol:    "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != "deny" {
		t.Errorf("want deny for unknown domain, got %s", out.Action)
	}
}

// ---------------------------------------------------------------------------
// Skill Actions
// ---------------------------------------------------------------------------

func TestEngine_EvaluateSkillActions_Critical(t *testing.T) {
	e := extEngine(t)
	out, err := e.EvaluateSkillActions(extCtx(t), SkillActionsInput{
		Severity: "CRITICAL",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.RuntimeAction != "block" {
		t.Errorf("want block runtime for CRITICAL, got %s", out.RuntimeAction)
	}
	if out.InstallAction != "block" {
		t.Errorf("want block install for CRITICAL, got %s", out.InstallAction)
	}
	if !out.ShouldBlock {
		t.Error("want should_block=true for CRITICAL")
	}
}

func TestEngine_EvaluateSkillActions_Low(t *testing.T) {
	e := extEngine(t)
	out, err := e.EvaluateSkillActions(extCtx(t), SkillActionsInput{
		Severity: "LOW",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.RuntimeAction != "allow" {
		t.Errorf("want allow runtime for LOW, got %s", out.RuntimeAction)
	}
	if out.ShouldBlock {
		t.Error("want should_block=false for LOW")
	}
}

func TestEngine_EvaluateSkillActions_MediumStrictBlocks(t *testing.T) {
	e := extEngine(t)
	out, err := e.EvaluateSkillActions(extCtx(t), SkillActionsInput{
		Severity:   "MEDIUM",
		TargetType: "skill",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.RuntimeAction != "block" {
		t.Errorf("want block runtime for MEDIUM/strict, got %s", out.RuntimeAction)
	}
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

func TestEngine_EvaluateAudit_Retain(t *testing.T) {
	e := extEngine(t)
	out, err := e.EvaluateAudit(extCtx(t), AuditInput{
		EventType:     "scan",
		Severity:      "MEDIUM",
		AgeDays:       10,
		ExportTargets: []string{"splunk"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Retain {
		t.Error("want retain=true for recent event")
	}
}

func TestEngine_EvaluateAudit_Expired(t *testing.T) {
	e := extEngine(t)
	out, err := e.EvaluateAudit(extCtx(t), AuditInput{
		EventType:     "admission",
		Severity:      "LOW",
		AgeDays:       500,
		ExportTargets: nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Retain {
		t.Error("want retain=false for expired LOW event")
	}
}

func TestEngine_EvaluateAudit_HighSeverityAlwaysRetained(t *testing.T) {
	e := extEngine(t)
	out, err := e.EvaluateAudit(extCtx(t), AuditInput{
		EventType:     "admission",
		Severity:      "CRITICAL",
		AgeDays:       9999,
		ExportTargets: []string{"splunk"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Retain {
		t.Error("want retain=true for CRITICAL regardless of age")
	}
	if len(out.ExportTo) == 0 {
		t.Error("want export_to to contain splunk for CRITICAL")
	}
}

// ---------------------------------------------------------------------------
// Sandbox
// ---------------------------------------------------------------------------

func TestEngine_EvaluateSandbox(t *testing.T) {
	e := extEngine(t)
	out, err := e.EvaluateSandbox(extCtx(t), SandboxInput{
		SkillName:            "test-skill",
		RequestedEndpoints:   []string{"api.github.com", "169.254.169.254"},
		RequestedPermissions: []string{"read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.DeniedFromRequest) == 0 {
		t.Error("want denied_from_request to contain blocked endpoint")
	}
}

// ---------------------------------------------------------------------------
// Guardrail
// ---------------------------------------------------------------------------

func TestEngine_EvaluateGuardrail_AllowClean(t *testing.T) {
	e := extEngine(t)
	out, err := e.EvaluateGuardrail(extCtx(t), GuardrailInput{
		Direction:   "prompt",
		Model:       "test",
		Mode:        "action",
		ScannerMode: "local",
		LocalResult: &GuardrailScanResult{
			Action:   "allow",
			Severity: "NONE",
			Findings: nil,
			Reason:   "",
		},
		ContentLength: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != "allow" {
		t.Errorf("want allow for clean guardrail, got %s", out.Action)
	}
}

func TestEngine_EvaluateGuardrail_BlockHighLocal(t *testing.T) {
	e := extEngine(t)
	out, err := e.EvaluateGuardrail(extCtx(t), GuardrailInput{
		Direction:   "prompt",
		Model:       "test",
		Mode:        "action",
		ScannerMode: "local",
		LocalResult: &GuardrailScanResult{
			Action:   "block",
			Severity: "HIGH",
			Findings: []string{"ignore previous"},
			Reason:   "matched: ignore previous",
		},
		ContentLength: 200,
	})
	if err != nil {
		t.Fatal(err)
	}
	// HIGH has severity_rank=3, block_threshold=3 → >=, so block
	if out.Action != "block" {
		t.Errorf("want block for HIGH local finding, got %s", out.Action)
	}
}

// ---------------------------------------------------------------------------
// Admission: install_action and file_action
// ---------------------------------------------------------------------------

func TestEngine_Admission_InstallAction(t *testing.T) {
	e := extEngine(t)
	out, err := e.Evaluate(extCtx(t), AdmissionInput{
		TargetType: "skill",
		TargetName: "vuln-skill",
		Path:       "/tmp/vuln",
		ScanResult: &ScanResultInput{
			MaxSeverity:   "CRITICAL",
			TotalFindings: 1,
			ScannerName:   "skill-scanner",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Verdict != "rejected" {
		t.Errorf("want rejected, got %s", out.Verdict)
	}
	if out.InstallAction != "block" {
		t.Errorf("want install_action=block, got %s", out.InstallAction)
	}
	if out.FileAction != "quarantine" {
		t.Errorf("want file_action=quarantine, got %s", out.FileAction)
	}
}

func TestEngine_Admission_PerScannerFindings(t *testing.T) {
	e := extEngine(t)
	out, err := e.Evaluate(extCtx(t), AdmissionInput{
		TargetType: "mcp",
		TargetName: "test-mcp",
		Path:       "/tmp/mcp",
		ScanResult: &ScanResultInput{
			MaxSeverity:   "HIGH",
			TotalFindings: 2,
			ScannerName:   "mcp-scanner",
			Findings: []FindingInput{
				{Severity: "HIGH", Scanner: "mcp-scanner", Title: "vuln1"},
				{Severity: "MEDIUM", Scanner: "mcp-scanner", Title: "vuln2"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Verdict != "rejected" {
		t.Errorf("want rejected for HIGH mcp, got %s", out.Verdict)
	}
}

// ---------------------------------------------------------------------------
// Reload
// ---------------------------------------------------------------------------

func TestEngine_Reload(t *testing.T) {
	e := extEngine(t)

	if err := e.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	out, err := e.Evaluate(extCtx(t), AdmissionInput{
		TargetType: "skill",
		TargetName: "test",
		Path:       "/tmp/test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Verdict != "scan" {
		t.Errorf("want scan after reload, got %s", out.Verdict)
	}
}
