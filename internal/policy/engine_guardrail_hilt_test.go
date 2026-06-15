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

// setupHILTRegoDir copies the production .rego files into a temp dir
// alongside a controlled data.json so we can exercise the input.hilt
// override contract without depending on whatever data.json the user's
// dev machine happens to have. The data shape mirrors what
// `defenseclaw policy activate` writes to ~/.defenseclaw/policies/rego/
// at install time.
//
// We pin block_threshold=4 so that HIGH (rank 3) does NOT trip the
// `block` branch — that lets us observe whether the policy reaches
// the `confirm` branch, which is the whole point of these tests.
func setupHILTRegoDir(t *testing.T, dataHILT map[string]interface{}) string {
	t.Helper()

	_, thisFile, _, _ := runtime.Caller(0)
	srcRegoDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "policies", "rego")
	if _, err := os.Stat(srcRegoDir); err != nil {
		t.Skipf("policies/rego not found at %s — skipping", srcRegoDir)
	}

	dir := t.TempDir()

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
		if len(name) > 10 && name[len(name)-10:] == "_test.rego" {
			continue
		}
		src, err := os.ReadFile(filepath.Join(srcRegoDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), src, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	guardrail := map[string]interface{}{
		"severity_rank": map[string]int{
			"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
		},
		"block_threshold":   4,
		"alert_threshold":   2,
		"cisco_trust_level": "full",
	}
	if dataHILT != nil {
		guardrail["hilt"] = dataHILT
	}

	data := map[string]interface{}{
		"config":            map[string]interface{}{},
		"actions":           map[string]interface{}{},
		"scanner_overrides": map[string]interface{}{},
		"severity_ranking":  map[string]int{"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1},
		"audit":             map[string]interface{}{},
		"firewall":          map[string]interface{}{"default_action": "deny"},
		"sandbox":           map[string]interface{}{},
		"guardrail":         guardrail,
	}

	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		t.Fatalf("marshal data: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data.json"), raw, 0o600); err != nil {
		t.Fatalf("write data.json: %v", err)
	}
	return dir
}

func hiltCtx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

func highLocal() *GuardrailScanResult {
	return &GuardrailScanResult{
		Action:   "block",
		Severity: "HIGH",
		Findings: []string{"ignore previous"},
		Reason:   "matched: ignore previous",
	}
}

// TestEngine_EvaluateGuardrail_InputHILTOverridesData pins the gateway
// SSOT contract: when the gateway passes input.hilt with enabled=true,
// the verdict is `confirm` even though data.guardrail.hilt is disabled
// (the historical out-of-sync state that motivated this work).
func TestEngine_EvaluateGuardrail_InputHILTOverridesData(t *testing.T) {
	dir := setupHILTRegoDir(t, map[string]interface{}{
		"enabled":      false, // stale data.json — the bug shape
		"min_severity": "HIGH",
	})
	e, err := New(dir)
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}

	out, err := e.EvaluateGuardrail(hiltCtx(t), GuardrailInput{
		Direction:   "prompt",
		Model:       "test",
		Mode:        "action",
		ScannerMode: "local",
		LocalResult: highLocal(),
		HILT: &GuardrailHILTInput{
			Enabled:     true, // live config.yaml — the source of truth
			MinSeverity: "HIGH",
		},
		ContentLength: 200,
	})
	if err != nil {
		t.Fatalf("EvaluateGuardrail: %v", err)
	}
	if out.Action != "confirm" {
		t.Errorf("input.hilt.enabled=true should win over stale data.guardrail.hilt.enabled=false; got action=%q (want confirm)", out.Action)
	}
	if out.Severity != "HIGH" {
		t.Errorf("severity should pass through unchanged; got %q (want HIGH)", out.Severity)
	}
}

// TestEngine_EvaluateGuardrail_InputHILTDisablesData covers the inverse:
// even if data.guardrail.hilt is enabled, an explicit input.hilt with
// enabled=false must downgrade to plain `alert`. This is the contract
// that lets operators flip HILT off in config.yaml without first
// regenerating data.json.
func TestEngine_EvaluateGuardrail_InputHILTDisablesData(t *testing.T) {
	dir := setupHILTRegoDir(t, map[string]interface{}{
		"enabled":      true,
		"min_severity": "HIGH",
	})
	e, err := New(dir)
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}

	out, err := e.EvaluateGuardrail(hiltCtx(t), GuardrailInput{
		Direction:   "prompt",
		Model:       "test",
		Mode:        "action",
		ScannerMode: "local",
		LocalResult: highLocal(),
		HILT: &GuardrailHILTInput{
			Enabled:     false,
			MinSeverity: "HIGH",
		},
		ContentLength: 200,
	})
	if err != nil {
		t.Fatalf("EvaluateGuardrail: %v", err)
	}
	if out.Action != "alert" {
		t.Errorf("input.hilt.enabled=false should win over data.guardrail.hilt.enabled=true; got action=%q (want alert)", out.Action)
	}
}

// TestEngine_EvaluateGuardrail_NilInputHILTFallsBackToData covers the
// backward-compat fallback. Older callers (api.go before this change,
// direct `opa eval` users, integration tests that build GuardrailInput
// without HILT) must keep working: a nil input.HILT means the policy
// reads data.guardrail.hilt as before.
func TestEngine_EvaluateGuardrail_NilInputHILTFallsBackToData(t *testing.T) {
	dir := setupHILTRegoDir(t, map[string]interface{}{
		"enabled":      true,
		"min_severity": "HIGH",
	})
	e, err := New(dir)
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}

	out, err := e.EvaluateGuardrail(hiltCtx(t), GuardrailInput{
		Direction:     "prompt",
		Model:         "test",
		Mode:          "action",
		ScannerMode:   "local",
		LocalResult:   highLocal(),
		HILT:          nil, // no input override -> fall back to data.json
		ContentLength: 200,
	})
	if err != nil {
		t.Fatalf("EvaluateGuardrail: %v", err)
	}
	if out.Action != "confirm" {
		t.Errorf("nil input.HILT should fall back to data.guardrail.hilt.enabled=true; got action=%q (want confirm)", out.Action)
	}
}

// TestEngine_EvaluateGuardrail_InputHILTRaisesMinSeverity verifies that
// raising input.hilt.min_severity above the finding's severity skips
// the confirm branch. This is the knob operators use to require HILT
// confirmation only on CRITICAL findings while leaving HIGH on alert.
func TestEngine_EvaluateGuardrail_InputHILTRaisesMinSeverity(t *testing.T) {
	dir := setupHILTRegoDir(t, nil) // no data fallback — input is the only source
	e, err := New(dir)
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}

	out, err := e.EvaluateGuardrail(hiltCtx(t), GuardrailInput{
		Direction:   "prompt",
		Model:       "test",
		Mode:        "action",
		ScannerMode: "local",
		LocalResult: highLocal(),
		HILT: &GuardrailHILTInput{
			Enabled:     true,
			MinSeverity: "CRITICAL",
		},
		ContentLength: 200,
	})
	if err != nil {
		t.Fatalf("EvaluateGuardrail: %v", err)
	}
	if out.Action != "alert" {
		t.Errorf("HIGH finding < min_severity=CRITICAL should not confirm; got action=%q (want alert)", out.Action)
	}
}
