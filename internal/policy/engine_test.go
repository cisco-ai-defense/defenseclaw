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

func setupRegoDir(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	admission := `package defenseclaw.admission

import rego.v1

default verdict := "scan"
default reason := "awaiting scan"

verdict := "blocked" if _is_blocked
reason := sprintf("%s '%s' is on the block list", [input.target_type, input.target_name]) if {
	verdict == "blocked"
}

verdict := "allowed" if {
	not _is_blocked
	_is_explicit_allow_listed
}
reason := sprintf("%s '%s' is on the allow list — scan skipped", [input.target_type, input.target_name]) if {
	not _is_blocked
	_is_explicit_allow_listed
}

verdict := "allowed" if {
	not _is_blocked
	not _is_explicit_allow_listed
	_is_policy_allow_listed
	data.config.allow_list_bypass_scan == true
}
reason := sprintf("%s '%s' is on the allow list — scan skipped", [input.target_type, input.target_name]) if {
	not _is_blocked
	not _is_explicit_allow_listed
	_is_policy_allow_listed
	data.config.allow_list_bypass_scan == true
}

verdict := "clean" if {
	not _is_blocked
	not _is_allow_bypassed
	_has_scan
	input.scan_result.total_findings == 0
}
reason := "scan clean" if {
	not _is_blocked
	not _is_allow_bypassed
	_has_scan
	input.scan_result.total_findings == 0
}

verdict := "rejected" if {
	not _is_blocked
	not _is_allow_bypassed
	_has_scan
	input.scan_result.total_findings > 0
	_should_reject
}
reason := sprintf("max severity %s triggers block per policy", [input.scan_result.max_severity]) if {
	not _is_blocked
	not _is_allow_bypassed
	_has_scan
	input.scan_result.total_findings > 0
	_should_reject
}

verdict := "warning" if {
	not _is_blocked
	not _is_allow_bypassed
	_has_scan
	input.scan_result.total_findings > 0
	not _should_reject
}
reason := sprintf("findings present (max %s) — allowed with warning", [input.scan_result.max_severity]) if {
	not _is_blocked
	not _is_allow_bypassed
	_has_scan
	input.scan_result.total_findings > 0
	not _should_reject
}

_is_blocked if {
	some entry in input.block_list
	entry.target_name == input.target_name
	entry.target_type == input.target_type
}

_is_explicit_allow_listed if {
	some entry in input.allow_list
	entry.target_name == input.target_name
	entry.target_type == input.target_type
}

_is_policy_allow_listed if {
	some entry in data.first_party_allow_list
	entry.target_name == input.target_name
	entry.target_type == input.target_type
	_path_matches_provenance(entry)
}

_path_matches_provenance(entry) if {
	not entry.source_path_contains
}
_path_matches_provenance(entry) if {
	count(entry.source_path_contains) == 0
}
_path_matches_provenance(entry) if {
	some prefix in entry.source_path_contains
	contains(lower(input.path), lower(prefix))
}

_is_allow_bypassed if {
	_is_explicit_allow_listed
}

_is_allow_bypassed if {
	_is_policy_allow_listed
	data.config.allow_list_bypass_scan == true
}

_has_scan if input.scan_result

verdict := "allowed" if {
	not _is_blocked
	not _is_allow_bypassed
	not _has_scan
	data.config.scan_on_install == false
}
reason := "scan_on_install disabled — allowed without scan" if {
	not _is_blocked
	not _is_allow_bypassed
	not _has_scan
	data.config.scan_on_install == false
}

_effective_action := action if {
	action := data.scanner_overrides[input.target_type][input.scan_result.max_severity]
} else := action if {
	action := data.actions[input.scan_result.max_severity]
}

_should_reject if {
	_effective_action.runtime == "block"
}

_should_reject if {
	_effective_action.install == "block"
}

file_action := action if {
	_has_scan
	action := _effective_action.file
}
file_action := "none" if {
	not _has_scan
}

install_action := action if {
	_has_scan
	action := _effective_action.install
}
install_action := "none" if {
	not _has_scan
}

runtime_action := action if {
	_has_scan
	action := _effective_action.runtime
}
runtime_action := "allow" if {
	not _has_scan
}
`

	data := map[string]interface{}{
		"config": map[string]interface{}{
			"allow_list_bypass_scan": true,
			"scan_on_install":        true,
		},
		"actions": map[string]interface{}{
			"CRITICAL": map[string]string{"runtime": "block", "file": "quarantine", "install": "block"},
			"HIGH":     map[string]string{"runtime": "block", "file": "quarantine", "install": "block"},
			"MEDIUM":   map[string]string{"runtime": "allow", "file": "none", "install": "none"},
			"LOW":      map[string]string{"runtime": "allow", "file": "none", "install": "none"},
			"INFO":     map[string]string{"runtime": "allow", "file": "none", "install": "none"},
		},
		"scanner_overrides": map[string]interface{}{},
		"first_party_allow_list": []map[string]interface{}{
			{"target_type": "plugin", "target_name": "defenseclaw", "reason": "first-party DefenseClaw plugin", "source_path_contains": []string{".defenseclaw", ".openclaw/extensions", ".zeptoclaw/extensions", ".claude/extensions", ".codex/extensions", ".codex-plugin"}},
			{"target_type": "skill", "target_name": "codeguard", "reason": "first-party DefenseClaw skill", "source_path_contains": []string{".defenseclaw", ".openclaw/workspace/skills", ".openclaw/skills", ".zeptoclaw/skills", ".claude/skills", ".codex/skills"}},
		},
	}

	if err := os.WriteFile(filepath.Join(dir, "admission.rego"), []byte(admission), 0o644); err != nil {
		t.Fatal(err)
	}

	dataBytes, _ := json.Marshal(data)
	if err := os.WriteFile(filepath.Join(dir, "data.json"), dataBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	return dir
}

func TestEngine_Blocked(t *testing.T) {
	dir := setupRegoDir(t)
	eng, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	out, err := eng.Evaluate(context.Background(), AdmissionInput{
		TargetType: "skill",
		TargetName: "evil-skill",
		Path:       "/tmp/skills/evil-skill",
		BlockList: []ListEntry{
			{TargetType: "skill", TargetName: "evil-skill", Reason: "malicious"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Verdict != "blocked" {
		t.Errorf("expected verdict blocked, got %q", out.Verdict)
	}
}

func TestEngine_Allowed(t *testing.T) {
	dir := setupRegoDir(t)
	eng, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	out, err := eng.Evaluate(context.Background(), AdmissionInput{
		TargetType: "skill",
		TargetName: "trusted-skill",
		Path:       "/tmp/skills/trusted-skill",
		AllowList: []ListEntry{
			{TargetType: "skill", TargetName: "trusted-skill", Reason: "pre-approved"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Verdict != "allowed" {
		t.Errorf("expected verdict allowed, got %q", out.Verdict)
	}
}

func TestEngine_ScanClean(t *testing.T) {
	dir := setupRegoDir(t)
	eng, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	out, err := eng.Evaluate(context.Background(), AdmissionInput{
		TargetType: "skill",
		TargetName: "safe-skill",
		Path:       "/tmp/skills/safe-skill",
		ScanResult: &ScanResultInput{MaxSeverity: "INFO", TotalFindings: 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Verdict != "clean" {
		t.Errorf("expected verdict clean, got %q", out.Verdict)
	}
}

func TestEngine_ScanRejected_Critical(t *testing.T) {
	dir := setupRegoDir(t)
	eng, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	out, err := eng.Evaluate(context.Background(), AdmissionInput{
		TargetType: "skill",
		TargetName: "bad-skill",
		Path:       "/tmp/skills/bad-skill",
		ScanResult: &ScanResultInput{MaxSeverity: "CRITICAL", TotalFindings: 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Verdict != "rejected" {
		t.Errorf("expected verdict rejected, got %q", out.Verdict)
	}
	if out.FileAction != "quarantine" {
		t.Errorf("expected file_action quarantine, got %q", out.FileAction)
	}
	if out.RuntimeAction != "block" {
		t.Errorf("expected runtime_action block, got %q", out.RuntimeAction)
	}
	if out.InstallAction != "block" {
		t.Errorf("expected install_action block, got %q", out.InstallAction)
	}
}

func TestEngine_ScanRejected_High(t *testing.T) {
	dir := setupRegoDir(t)
	eng, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	out, err := eng.Evaluate(context.Background(), AdmissionInput{
		TargetType: "mcp",
		TargetName: "risky-server",
		Path:       "/tmp/mcp/risky-server",
		ScanResult: &ScanResultInput{MaxSeverity: "HIGH", TotalFindings: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Verdict != "rejected" {
		t.Errorf("expected verdict rejected, got %q", out.Verdict)
	}
}

func TestEngine_ScanWarning_Medium(t *testing.T) {
	dir := setupRegoDir(t)
	eng, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	out, err := eng.Evaluate(context.Background(), AdmissionInput{
		TargetType: "skill",
		TargetName: "iffy-skill",
		Path:       "/tmp/skills/iffy-skill",
		ScanResult: &ScanResultInput{MaxSeverity: "MEDIUM", TotalFindings: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Verdict != "warning" {
		t.Errorf("expected verdict warning, got %q", out.Verdict)
	}
	if out.FileAction != "none" {
		t.Errorf("expected file_action none, got %q", out.FileAction)
	}
}

func TestEngine_ScanWarning_Low(t *testing.T) {
	dir := setupRegoDir(t)
	eng, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	out, err := eng.Evaluate(context.Background(), AdmissionInput{
		TargetType: "skill",
		TargetName: "minor-skill",
		Path:       "/tmp/skills/minor-skill",
		ScanResult: &ScanResultInput{MaxSeverity: "LOW", TotalFindings: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Verdict != "warning" {
		t.Errorf("expected verdict warning, got %q", out.Verdict)
	}
}

func TestEngine_BlockBeatsAllow(t *testing.T) {
	dir := setupRegoDir(t)
	eng, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	out, err := eng.Evaluate(context.Background(), AdmissionInput{
		TargetType: "skill",
		TargetName: "conflict-skill",
		Path:       "/tmp/skills/conflict-skill",
		BlockList: []ListEntry{
			{TargetType: "skill", TargetName: "conflict-skill", Reason: "security"},
		},
		AllowList: []ListEntry{
			{TargetType: "skill", TargetName: "conflict-skill", Reason: "approved"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Verdict != "blocked" {
		t.Errorf("expected block to take precedence over allow, got %q", out.Verdict)
	}
}

func TestEngine_NoScanResult_ReturnsAwaitingScan(t *testing.T) {
	dir := setupRegoDir(t)
	eng, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	out, err := eng.Evaluate(context.Background(), AdmissionInput{
		TargetType: "skill",
		TargetName: "new-skill",
		Path:       "/tmp/skills/new-skill",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Verdict != "scan" {
		t.Errorf("expected verdict scan (awaiting), got %q", out.Verdict)
	}
}

func TestEngine_Compile(t *testing.T) {
	dir := setupRegoDir(t)
	eng, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Compile(); err != nil {
		t.Errorf("compile failed: %v", err)
	}
}

// TestEngine_FirstPartyAllowList_AllConnectorPaths is the regression
// test for S3.2 / F10. Before that change the first-party
// allow-list only knew about the OpenClaw skill paths
// (.openclaw/workspace/skills, .openclaw/skills), so the codeguard
// skill scanned from a Codex / Claude Code / ZeptoClaw home would
// fall through to the standard severity-action rules and get
// quarantined under strict policy. The fix extends
// source_path_contains to cover all four built-in connectors plus
// the bare ~/.defenseclaw/ install location.
//
// The test drives the Rego engine end-to-end so a future refactor
// that splits the allow-list out of policies/strict.yaml without
// keeping data.json in sync still trips this assertion.
func TestEngine_FirstPartyAllowList_AllConnectorPaths(t *testing.T) {
	dir := setupRegoDir(t)
	eng, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	// One representative path per connector home. We include both the
	// "extensions" (plugin) and "skills" (skill) flavors so a future
	// path drift on either axis is caught here, not deeper in the
	// scanner where the failure mode is "everything blocks under
	// strict".
	cases := []struct {
		name       string
		targetType string
		targetName string
		path       string
	}{
		{"openclaw_skill", "skill", "codeguard", "/tmp/.openclaw/skills/codeguard"},
		{"openclaw_workspace_skill", "skill", "codeguard", "/tmp/.openclaw/workspace/skills/codeguard"},
		{"zeptoclaw_skill", "skill", "codeguard", "/tmp/.zeptoclaw/skills/codeguard"},
		{"claudecode_skill", "skill", "codeguard", "/tmp/.claude/skills/codeguard"},
		{"codex_skill", "skill", "codeguard", "/tmp/.codex/skills/codeguard"},
		{"openclaw_plugin", "plugin", "defenseclaw", "/tmp/.openclaw/extensions/defenseclaw"},
		{"zeptoclaw_plugin", "plugin", "defenseclaw", "/tmp/.zeptoclaw/extensions/defenseclaw"},
		{"claudecode_plugin", "plugin", "defenseclaw", "/tmp/.claude/extensions/defenseclaw"},
		{"codex_plugin", "plugin", "defenseclaw", "/tmp/.codex/extensions/defenseclaw"},
		{"defenseclaw_root", "skill", "codeguard", "/tmp/.defenseclaw/skills/codeguard"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			out, err := eng.Evaluate(context.Background(), AdmissionInput{
				TargetType: tc.targetType,
				TargetName: tc.targetName,
				Path:       tc.path,
				ScanResult: &ScanResultInput{MaxSeverity: "MEDIUM", TotalFindings: 1},
			})
			if err != nil {
				t.Fatalf("Evaluate(%s): %v", tc.path, err)
			}
			// allow_list_bypass_scan=true in setupRegoDir, so the
			// allow-list match should produce verdict=allowed
			// instead of warning/blocked.
			if out.Verdict != "allowed" {
				t.Errorf("verdict for %s=%q at %s: got %q, want allowed (path not in first_party_allow_list?)",
					tc.targetType, tc.targetName, tc.path, out.Verdict)
			}
		})
	}
}

func TestMergeSupplementalData(t *testing.T) {
	t.Run("file missing is a silent no-op", func(t *testing.T) {
		data := map[string]interface{}{"existing": "value"}
		mergeSupplementalData(t.TempDir(), data, "nonexistent.json")
		if len(data) != 1 {
			t.Errorf("expected 1 key, got %d", len(data))
		}
	})

	t.Run("valid file merges top-level keys", func(t *testing.T) {
		dir := t.TempDir()
		extra := `{"sandbox":{"update_policy":false},"firewall":{"default_action":"deny"}}`
		os.WriteFile(filepath.Join(dir, "extra.json"), []byte(extra), 0o600)

		data := map[string]interface{}{"config": "original"}
		mergeSupplementalData(dir, data, "extra.json")

		if _, ok := data["sandbox"]; !ok {
			t.Error("expected sandbox key to be merged")
		}
		if _, ok := data["firewall"]; !ok {
			t.Error("expected firewall key to be merged")
		}
		if data["config"] != "original" {
			t.Error("existing key should be untouched")
		}
	})

	t.Run("invalid JSON is a silent no-op", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{not json"), 0o600)

		data := map[string]interface{}{"keep": true}
		mergeSupplementalData(dir, data, "bad.json")

		if len(data) != 1 {
			t.Errorf("expected 1 key, got %d", len(data))
		}
	})

	t.Run("empty file is a silent no-op", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "empty.json"), []byte(""), 0o600)

		data := map[string]interface{}{"keep": true}
		mergeSupplementalData(dir, data, "empty.json")

		if len(data) != 1 {
			t.Errorf("expected 1 key, got %d", len(data))
		}
	})

	t.Run("overlapping key overwrites", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "overlap.json"), []byte(`{"config":"new"}`), 0o600)

		data := map[string]interface{}{"config": "old"}
		mergeSupplementalData(dir, data, "overlap.json")

		if data["config"] != "new" {
			t.Errorf("expected overlapping key to be overwritten, got %v", data["config"])
		}
	})
}
