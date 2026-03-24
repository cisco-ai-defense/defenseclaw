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
	_is_allow_listed
	data.config.allow_list_bypass_scan == true
}
reason := sprintf("%s '%s' is on the allow list — scan skipped", [input.target_type, input.target_name]) if {
	not _is_blocked
	_is_allow_listed
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

_is_allow_listed if {
	some entry in input.allow_list
	entry.target_name == input.target_name
	entry.target_type == input.target_type
}

_is_allow_bypassed if {
	_is_allow_listed
	data.config.allow_list_bypass_scan == true
}

_has_scan if input.scan_result

_should_reject if {
	data.actions[input.scan_result.max_severity].runtime == "block"
}

file_action := action if {
	_has_scan
	action := data.actions[input.scan_result.max_severity].file
}
file_action := "none" if {
	not _has_scan
}
`

	data := map[string]interface{}{
		"config": map[string]interface{}{
			"allow_list_bypass_scan": true,
		},
		"actions": map[string]interface{}{
			"CRITICAL": map[string]string{"runtime": "block", "file": "quarantine"},
			"HIGH":     map[string]string{"runtime": "block", "file": "quarantine"},
			"MEDIUM":   map[string]string{"runtime": "allow", "file": "none"},
			"LOW":      map[string]string{"runtime": "allow", "file": "none"},
			"INFO":     map[string]string{"runtime": "allow", "file": "none"},
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
