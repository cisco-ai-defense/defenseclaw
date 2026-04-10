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
	"testing"
)

// setupPolicyDir creates a temp rego dir with the admission.rego and a
// data.json configured according to the given policy profile.
// This simulates what "defenseclaw policy activate" does: it writes the
// severity→action mapping into data.json which OPA reads.
func setupPolicyDir(t *testing.T, actions map[string]map[string]string, allowBypass bool) string {
	t.Helper()

	dir := setupRegoDir(t) // base rego setup with default actions

	// Overwrite data.json with the policy-specific actions
	data := map[string]interface{}{
		"config": map[string]interface{}{
			"allow_list_bypass_scan": allowBypass,
		},
		"actions": actions,
	}

	dataBytes, _ := json.Marshal(data)
	if err := os.WriteFile(filepath.Join(dir, "data.json"), dataBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	return dir
}

// --------------------------------------------------------------------------
// Test: Default policy → CRITICAL plugin scan → rejected + quarantine
// --------------------------------------------------------------------------
func TestPolicyScan_Default_CriticalPlugin_Rejected(t *testing.T) {
	dir := setupPolicyDir(t, map[string]map[string]string{
		"CRITICAL": {"runtime": "block", "file": "quarantine"},
		"HIGH":     {"runtime": "block", "file": "quarantine"},
		"MEDIUM":   {"runtime": "allow", "file": "none"},
		"LOW":      {"runtime": "allow", "file": "none"},
		"INFO":     {"runtime": "allow", "file": "none"},
	}, true)

	eng, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	out, err := eng.Evaluate(context.Background(), AdmissionInput{
		TargetType: "plugin",
		TargetName: "malicious-plugin",
		Path:       "/tmp/plugins/malicious-plugin",
		ScanResult: &ScanResultInput{MaxSeverity: "CRITICAL", TotalFindings: 2},
	})
	if err != nil {
		t.Fatal(err)
	}

	if out.Verdict != "rejected" {
		t.Errorf("default policy: CRITICAL plugin should be rejected, got %q", out.Verdict)
	}
	if out.FileAction != "quarantine" {
		t.Errorf("default policy: CRITICAL plugin should be quarantined, got file_action=%q", out.FileAction)
	}
}

// --------------------------------------------------------------------------
// Test: Default policy → MEDIUM plugin scan → warning (no quarantine)
// --------------------------------------------------------------------------
func TestPolicyScan_Default_MediumPlugin_Warning(t *testing.T) {
	dir := setupPolicyDir(t, map[string]map[string]string{
		"CRITICAL": {"runtime": "block", "file": "quarantine"},
		"HIGH":     {"runtime": "block", "file": "quarantine"},
		"MEDIUM":   {"runtime": "allow", "file": "none"},
		"LOW":      {"runtime": "allow", "file": "none"},
		"INFO":     {"runtime": "allow", "file": "none"},
	}, true)

	eng, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	out, err := eng.Evaluate(context.Background(), AdmissionInput{
		TargetType: "plugin",
		TargetName: "iffy-plugin",
		Path:       "/tmp/plugins/iffy-plugin",
		ScanResult: &ScanResultInput{MaxSeverity: "MEDIUM", TotalFindings: 3},
	})
	if err != nil {
		t.Fatal(err)
	}

	if out.Verdict != "warning" {
		t.Errorf("default policy: MEDIUM plugin should be warning, got %q", out.Verdict)
	}
	if out.FileAction != "none" {
		t.Errorf("default policy: MEDIUM plugin should NOT be quarantined, got file_action=%q", out.FileAction)
	}
}

// --------------------------------------------------------------------------
// Test: Strict policy → MEDIUM plugin scan → rejected + quarantine
// --------------------------------------------------------------------------
func TestPolicyScan_Strict_MediumPlugin_Rejected(t *testing.T) {
	// Strict: MEDIUM and above trigger block + quarantine
	dir := setupPolicyDir(t, map[string]map[string]string{
		"CRITICAL": {"runtime": "block", "file": "quarantine"},
		"HIGH":     {"runtime": "block", "file": "quarantine"},
		"MEDIUM":   {"runtime": "block", "file": "quarantine"},
		"LOW":      {"runtime": "allow", "file": "none"},
		"INFO":     {"runtime": "allow", "file": "none"},
	}, false) // strict: no allow-list bypass

	eng, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	out, err := eng.Evaluate(context.Background(), AdmissionInput{
		TargetType: "plugin",
		TargetName: "medium-risk-plugin",
		Path:       "/tmp/plugins/medium-risk-plugin",
		ScanResult: &ScanResultInput{MaxSeverity: "MEDIUM", TotalFindings: 1},
	})
	if err != nil {
		t.Fatal(err)
	}

	if out.Verdict != "rejected" {
		t.Errorf("strict policy: MEDIUM plugin should be rejected, got %q", out.Verdict)
	}
	if out.FileAction != "quarantine" {
		t.Errorf("strict policy: MEDIUM plugin should be quarantined, got file_action=%q", out.FileAction)
	}
}

// --------------------------------------------------------------------------
// Test: Strict policy → explicit allow still overrides scan bypass config
// --------------------------------------------------------------------------
func TestPolicyScan_Strict_ExplicitAllowStillAllowed(t *testing.T) {
	dir := setupPolicyDir(t, map[string]map[string]string{
		"CRITICAL": {"runtime": "block", "file": "quarantine"},
		"HIGH":     {"runtime": "block", "file": "quarantine"},
		"MEDIUM":   {"runtime": "block", "file": "quarantine"},
		"LOW":      {"runtime": "allow", "file": "none"},
		"INFO":     {"runtime": "allow", "file": "none"},
	}, false) // strict: no allow-list bypass

	eng, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Explicit allow entries override policy bypass settings.
	out, err := eng.Evaluate(context.Background(), AdmissionInput{
		TargetType: "plugin",
		TargetName: "trusted-plugin",
		Path:       "/tmp/plugins/trusted-plugin",
		AllowList: []ListEntry{
			{TargetType: "plugin", TargetName: "trusted-plugin", Reason: "vendor approved"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if out.Verdict != "allowed" {
		t.Errorf("strict policy: explicit allow should still be 'allowed', got %q", out.Verdict)
	}
}

// --------------------------------------------------------------------------
// Test: Permissive policy → HIGH plugin scan → warning (not rejected)
// --------------------------------------------------------------------------
func TestPolicyScan_Permissive_HighPlugin_Warning(t *testing.T) {
	// Permissive: only CRITICAL triggers block
	dir := setupPolicyDir(t, map[string]map[string]string{
		"CRITICAL": {"runtime": "block", "file": "quarantine"},
		"HIGH":     {"runtime": "allow", "file": "none"},
		"MEDIUM":   {"runtime": "allow", "file": "none"},
		"LOW":      {"runtime": "allow", "file": "none"},
		"INFO":     {"runtime": "allow", "file": "none"},
	}, true)

	eng, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	out, err := eng.Evaluate(context.Background(), AdmissionInput{
		TargetType: "plugin",
		TargetName: "high-risk-plugin",
		Path:       "/tmp/plugins/high-risk-plugin",
		ScanResult: &ScanResultInput{MaxSeverity: "HIGH", TotalFindings: 5},
	})
	if err != nil {
		t.Fatal(err)
	}

	if out.Verdict != "warning" {
		t.Errorf("permissive policy: HIGH plugin should be warning, got %q", out.Verdict)
	}
	if out.FileAction != "none" {
		t.Errorf("permissive policy: HIGH plugin should NOT be quarantined, got file_action=%q", out.FileAction)
	}
}

// --------------------------------------------------------------------------
// Test: Permissive policy → CRITICAL plugin scan → still rejected
// --------------------------------------------------------------------------
func TestPolicyScan_Permissive_CriticalPlugin_StillRejected(t *testing.T) {
	dir := setupPolicyDir(t, map[string]map[string]string{
		"CRITICAL": {"runtime": "block", "file": "quarantine"},
		"HIGH":     {"runtime": "allow", "file": "none"},
		"MEDIUM":   {"runtime": "allow", "file": "none"},
		"LOW":      {"runtime": "allow", "file": "none"},
		"INFO":     {"runtime": "allow", "file": "none"},
	}, true)

	eng, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	out, err := eng.Evaluate(context.Background(), AdmissionInput{
		TargetType: "plugin",
		TargetName: "truly-bad-plugin",
		Path:       "/tmp/plugins/truly-bad-plugin",
		ScanResult: &ScanResultInput{MaxSeverity: "CRITICAL", TotalFindings: 1},
	})
	if err != nil {
		t.Fatal(err)
	}

	if out.Verdict != "rejected" {
		t.Errorf("permissive policy: CRITICAL plugin must still be rejected, got %q", out.Verdict)
	}
	if out.FileAction != "quarantine" {
		t.Errorf("permissive policy: CRITICAL plugin must still be quarantined, got file_action=%q", out.FileAction)
	}
}

// --------------------------------------------------------------------------
// Test: Same scan output, different policies → different verdicts
// --------------------------------------------------------------------------
func TestPolicyScan_SameScan_DifferentPolicies(t *testing.T) {
	scanInput := &ScanResultInput{MaxSeverity: "MEDIUM", TotalFindings: 2}
	target := AdmissionInput{
		TargetType: "plugin",
		TargetName: "test-plugin",
		Path:       "/tmp/plugins/test-plugin",
		ScanResult: scanInput,
	}

	// Default policy: MEDIUM → warning
	defaultDir := setupPolicyDir(t, map[string]map[string]string{
		"CRITICAL": {"runtime": "block", "file": "quarantine"},
		"HIGH":     {"runtime": "block", "file": "quarantine"},
		"MEDIUM":   {"runtime": "allow", "file": "none"},
		"LOW":      {"runtime": "allow", "file": "none"},
		"INFO":     {"runtime": "allow", "file": "none"},
	}, true)

	defaultEng, err := New(defaultDir)
	if err != nil {
		t.Fatal(err)
	}

	defaultOut, err := defaultEng.Evaluate(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}

	// Strict policy: MEDIUM → rejected
	strictDir := setupPolicyDir(t, map[string]map[string]string{
		"CRITICAL": {"runtime": "block", "file": "quarantine"},
		"HIGH":     {"runtime": "block", "file": "quarantine"},
		"MEDIUM":   {"runtime": "block", "file": "quarantine"},
		"LOW":      {"runtime": "allow", "file": "none"},
		"INFO":     {"runtime": "allow", "file": "none"},
	}, false)

	strictEng, err := New(strictDir)
	if err != nil {
		t.Fatal(err)
	}

	strictOut, err := strictEng.Evaluate(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}

	if defaultOut.Verdict != "warning" {
		t.Errorf("default policy: expected warning for MEDIUM, got %q", defaultOut.Verdict)
	}
	if strictOut.Verdict != "rejected" {
		t.Errorf("strict policy: expected rejected for MEDIUM, got %q", strictOut.Verdict)
	}
	if strictOut.FileAction != "quarantine" {
		t.Errorf("strict policy: expected quarantine for MEDIUM, got %q", strictOut.FileAction)
	}

	// Same scan, different outcome: this proves the policy drives the verdict
	if defaultOut.Verdict == strictOut.Verdict {
		t.Error("same scan output should produce different verdicts under different policies")
	}
}

// --------------------------------------------------------------------------
// Test: Clean plugin scan → clean verdict regardless of policy
// --------------------------------------------------------------------------
func TestPolicyScan_CleanPlugin_AlwaysClean(t *testing.T) {
	policies := []struct {
		name    string
		actions map[string]map[string]string
	}{
		{"default", map[string]map[string]string{
			"CRITICAL": {"runtime": "block", "file": "quarantine"},
			"HIGH":     {"runtime": "block", "file": "quarantine"},
			"MEDIUM":   {"runtime": "allow", "file": "none"},
		}},
		{"strict", map[string]map[string]string{
			"CRITICAL": {"runtime": "block", "file": "quarantine"},
			"HIGH":     {"runtime": "block", "file": "quarantine"},
			"MEDIUM":   {"runtime": "block", "file": "quarantine"},
		}},
	}

	for _, pol := range policies {
		t.Run(pol.name, func(t *testing.T) {
			dir := setupPolicyDir(t, pol.actions, true)
			eng, err := New(dir)
			if err != nil {
				t.Fatal(err)
			}

			out, err := eng.Evaluate(context.Background(), AdmissionInput{
				TargetType: "plugin",
				TargetName: "safe-plugin",
				Path:       "/tmp/plugins/safe-plugin",
				ScanResult: &ScanResultInput{MaxSeverity: "INFO", TotalFindings: 0},
			})
			if err != nil {
				t.Fatal(err)
			}

			if out.Verdict != "clean" {
				t.Errorf("%s policy: clean scan should always be clean, got %q", pol.name, out.Verdict)
			}
		})
	}
}

// --------------------------------------------------------------------------
// Test: Policy works for all target types (skill, mcp, plugin)
// --------------------------------------------------------------------------
func TestPolicyScan_AllTargetTypes(t *testing.T) {
	dir := setupPolicyDir(t, map[string]map[string]string{
		"CRITICAL": {"runtime": "block", "file": "quarantine"},
		"HIGH":     {"runtime": "block", "file": "quarantine"},
		"MEDIUM":   {"runtime": "allow", "file": "none"},
	}, true)

	eng, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	for _, targetType := range []string{"skill", "mcp", "plugin"} {
		t.Run(targetType, func(t *testing.T) {
			out, err := eng.Evaluate(context.Background(), AdmissionInput{
				TargetType: targetType,
				TargetName: "test-" + targetType,
				Path:       "/tmp/" + targetType + "/test",
				ScanResult: &ScanResultInput{MaxSeverity: "HIGH", TotalFindings: 1},
			})
			if err != nil {
				t.Fatal(err)
			}

			if out.Verdict != "rejected" {
				t.Errorf("%s: expected rejected for HIGH, got %q", targetType, out.Verdict)
			}
			if out.FileAction != "quarantine" {
				t.Errorf("%s: expected quarantine for HIGH, got %q", targetType, out.FileAction)
			}
		})
	}
}
