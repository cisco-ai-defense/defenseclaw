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
)

// setupBudgetRegoDir copies the budget policy + supplementary policies into
// a temp dir and writes a controlled data.json with a well-known limits
// table. We copy the full rego set so shared helpers (e.g. severity_rank)
// are available during compilation.
func setupBudgetRegoDir(t *testing.T, budgetData map[string]interface{}) string {
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
		// Skip Rego unit-test files — they're parsed with opa test, not
		// the runtime engine.
		if len(name) > 10 && name[len(name)-10:] == "_test.rego" {
			continue
		}
		src, _ := os.ReadFile(filepath.Join(srcRegoDir, name))
		_ = os.WriteFile(filepath.Join(dir, name), src, 0o644)
	}

	data := map[string]interface{}{
		"config": map[string]interface{}{
			"policy_name":                   "budget-test",
			"allow_list_bypass_scan":        true,
			"scan_on_install":               true,
			"max_enforcement_delay_seconds": 1,
		},
		"actions":           map[string]interface{}{},
		"scanner_overrides": map[string]interface{}{},
		"severity_ranking": map[string]int{
			"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1,
		},
		"audit": map[string]interface{}{},
		"firewall": map[string]interface{}{
			"default_action":       "allow",
			"blocked_destinations": []string{},
			"allowed_domains":      []string{},
			"allowed_ports":        []int{},
		},
		"sandbox": map[string]interface{}{
			"update_policy":           true,
			"default_permissions":     []string{},
			"denied_endpoints_global": []string{},
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
		"budget": budgetData,
	}

	raw, _ := json.MarshalIndent(data, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "data.json"), raw, 0o644); err != nil {
		t.Fatalf("write data.json: %v", err)
	}
	return dir
}

func newBudgetEngine(t *testing.T, budgetData map[string]interface{}) *Engine {
	t.Helper()
	e, err := New(setupBudgetRegoDir(t, budgetData))
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	return e
}

func defaultBudgetData() map[string]interface{} {
	return map[string]interface{}{
		"subjects": map[string]interface{}{
			"default": map[string]interface{}{
				"tokens_per_minute":   10000,
				"tokens_per_hour":     100000,
				"tokens_per_day":      1000000,
				"requests_per_minute": 60,
				"requests_per_hour":   1000,
				"requests_per_day":    10000,
				"cost_per_hour":       5.0,
				"cost_per_day":        50.0,
			},
		},
	}
}

func zeroUsage() BudgetUsage {
	return BudgetUsage{}
}

func TestEvaluateBudget_AllowWithinLimits(t *testing.T) {
	e := newBudgetEngine(t, defaultBudgetData())

	out, err := e.EvaluateBudget(context.Background(), BudgetInput{
		Subject:         "user:alice",
		Model:           "gpt-4o",
		EstimatedTokens: 500,
		EstimatedCost:   0.01,
		Usage:           zeroUsage(),
	})
	if err != nil {
		t.Fatalf("EvaluateBudget: %v", err)
	}
	if out.Action != "allow" {
		t.Fatalf("expected allow, got %q (reason=%q)", out.Action, out.Reason)
	}
}

func TestEvaluateBudget_DenyTokensPerMinute(t *testing.T) {
	e := newBudgetEngine(t, defaultBudgetData())

	out, err := e.EvaluateBudget(context.Background(), BudgetInput{
		Subject:         "user:alice",
		Model:           "gpt-4o",
		EstimatedTokens: 500,
		EstimatedCost:   0.01,
		Usage: BudgetUsage{
			TokensLastMinute: 9600,
		},
	})
	if err != nil {
		t.Fatalf("EvaluateBudget: %v", err)
	}
	if out.Action != "deny" {
		t.Fatalf("expected deny, got %q (reason=%q)", out.Action, out.Reason)
	}
	if out.Rule != "tokens_per_minute" {
		t.Fatalf("expected rule tokens_per_minute, got %q", out.Rule)
	}
}

func TestEvaluateBudget_DenyRequestsPerMinute(t *testing.T) {
	e := newBudgetEngine(t, defaultBudgetData())

	out, err := e.EvaluateBudget(context.Background(), BudgetInput{
		Subject:         "user:alice",
		Model:           "gpt-4o",
		EstimatedTokens: 10,
		EstimatedCost:   0.0001,
		Usage: BudgetUsage{
			RequestsLastMinute: 60,
		},
	})
	if err != nil {
		t.Fatalf("EvaluateBudget: %v", err)
	}
	if out.Action != "deny" {
		t.Fatalf("expected deny, got %q", out.Action)
	}
	if out.Rule != "requests_per_minute" {
		t.Fatalf("expected rule requests_per_minute, got %q", out.Rule)
	}
}

func TestEvaluateBudget_DenyCostPerHour(t *testing.T) {
	e := newBudgetEngine(t, defaultBudgetData())

	out, err := e.EvaluateBudget(context.Background(), BudgetInput{
		Subject:         "user:alice",
		Model:           "gpt-4o",
		EstimatedTokens: 100,
		EstimatedCost:   0.05,
		Usage: BudgetUsage{
			CostLastHour: 4.99,
		},
	})
	if err != nil {
		t.Fatalf("EvaluateBudget: %v", err)
	}
	if out.Action != "deny" {
		t.Fatalf("expected deny, got %q (reason=%q)", out.Action, out.Reason)
	}
	if out.Rule != "cost_per_hour" {
		t.Fatalf("expected rule cost_per_hour, got %q", out.Rule)
	}
}

func TestEvaluateBudget_SubjectOverride(t *testing.T) {
	data := map[string]interface{}{
		"subjects": map[string]interface{}{
			"default": map[string]interface{}{
				"tokens_per_minute":   10000,
				"tokens_per_hour":     100000,
				"tokens_per_day":      1000000,
				"requests_per_minute": 60,
				"requests_per_hour":   1000,
				"requests_per_day":    10000,
				"cost_per_hour":       5.0,
				"cost_per_day":        50.0,
			},
			"user:limited": map[string]interface{}{
				"tokens_per_minute":   100,
				"tokens_per_hour":     1000,
				"tokens_per_day":      10000,
				"requests_per_minute": 5,
				"requests_per_hour":   100,
				"requests_per_day":    500,
				"cost_per_hour":       0.10,
				"cost_per_day":        1.0,
			},
		},
	}
	e := newBudgetEngine(t, data)

	out, err := e.EvaluateBudget(context.Background(), BudgetInput{
		Subject:         "user:limited",
		Model:           "gpt-4o",
		EstimatedTokens: 200,
		EstimatedCost:   0.0001,
		Usage:           zeroUsage(),
	})
	if err != nil {
		t.Fatalf("EvaluateBudget: %v", err)
	}
	if out.Action != "deny" {
		t.Fatalf("expected deny for user:limited, got %q", out.Action)
	}
	if out.Rule != "tokens_per_minute" {
		t.Fatalf("expected rule tokens_per_minute, got %q", out.Rule)
	}
}

func TestEvaluateBudget_UnknownSubjectUsesDefault(t *testing.T) {
	e := newBudgetEngine(t, defaultBudgetData())

	out, err := e.EvaluateBudget(context.Background(), BudgetInput{
		Subject:         "user:stranger",
		Model:           "gpt-4o",
		EstimatedTokens: 500,
		EstimatedCost:   0.01,
		Usage:           zeroUsage(),
	})
	if err != nil {
		t.Fatalf("EvaluateBudget: %v", err)
	}
	if out.Action != "allow" {
		t.Fatalf("expected allow, got %q (reason=%q)", out.Action, out.Reason)
	}
}

func TestEvaluateBudget_ZeroLimitUnlimited(t *testing.T) {
	data := map[string]interface{}{
		"subjects": map[string]interface{}{
			"default": map[string]interface{}{
				"tokens_per_minute":   0,
				"tokens_per_hour":     0,
				"tokens_per_day":      0,
				"requests_per_minute": 0,
				"requests_per_hour":   0,
				"requests_per_day":    0,
				"cost_per_hour":       0,
				"cost_per_day":        0,
			},
		},
	}
	e := newBudgetEngine(t, data)

	out, err := e.EvaluateBudget(context.Background(), BudgetInput{
		Subject:         "user:alice",
		Model:           "gpt-4o",
		EstimatedTokens: 999999,
		EstimatedCost:   999,
		Usage: BudgetUsage{
			TokensLastMinute:   99999,
			RequestsLastMinute: 9999,
			CostLastHour:       9999,
			CostLastDay:        9999,
		},
	})
	if err != nil {
		t.Fatalf("EvaluateBudget: %v", err)
	}
	if out.Action != "allow" {
		t.Fatalf("expected allow, got %q (reason=%q)", out.Action, out.Reason)
	}
}

func TestReadPath_Budget(t *testing.T) {
	data := defaultBudgetData()
	data["pricing"] = map[string]interface{}{
		"gpt-4o": map[string]float64{
			"input_per_1k":  0.0025,
			"output_per_1k": 0.010,
		},
	}
	e := newBudgetEngine(t, data)

	v := e.ReadPath("budget/pricing")
	if v == nil {
		t.Fatalf("expected pricing table, got nil")
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map, got %T", v)
	}
	if _, ok := m["gpt-4o"]; !ok {
		t.Fatalf("expected gpt-4o entry in %v", m)
	}
}
