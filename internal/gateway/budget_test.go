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

package gateway

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/policy"
)

// ---------------------------------------------------------------------------
// BudgetTracker
// ---------------------------------------------------------------------------

func TestBudgetTracker_SnapshotEmpty(t *testing.T) {
	tr := NewBudgetTracker()
	u := tr.Snapshot("user:bob")
	if u.TokensLastMinute != 0 || u.RequestsLastMinute != 0 {
		t.Fatalf("expected zero snapshot, got %+v", u)
	}
}

func TestBudgetTracker_RecordAndSnapshot(t *testing.T) {
	tr := NewBudgetTracker()
	now := time.Now()
	tr.now = func() time.Time { return now }

	tr.Record("user:alice", 100, 0.01)
	tr.Record("user:alice", 200, 0.02)

	u := tr.Snapshot("user:alice")
	if u.TokensLastMinute != 300 {
		t.Fatalf("tokens_last_minute=%d, want 300", u.TokensLastMinute)
	}
	if u.RequestsLastMinute != 2 {
		t.Fatalf("requests_last_minute=%d, want 2", u.RequestsLastMinute)
	}
	if u.TokensLastHour != 300 {
		t.Fatalf("tokens_last_hour=%d, want 300", u.TokensLastHour)
	}
	if u.CostLastHour < 0.029 || u.CostLastHour > 0.031 {
		t.Fatalf("cost_last_hour=%f, want ~0.03", u.CostLastHour)
	}
}

func TestBudgetTracker_MinuteRollover(t *testing.T) {
	tr := NewBudgetTracker()
	base := time.Now()
	tr.now = func() time.Time { return base }
	tr.Record("user:alice", 100, 0.01)

	// Advance past minute window — tokens_last_minute should drop.
	tr.now = func() time.Time { return base.Add(61 * time.Second) }
	u := tr.Snapshot("user:alice")
	if u.TokensLastMinute != 0 {
		t.Fatalf("expected minute rollover, got %d", u.TokensLastMinute)
	}
	// Hour window still holds the value.
	if u.TokensLastHour != 100 {
		t.Fatalf("tokens_last_hour=%d, want 100", u.TokensLastHour)
	}
}

func TestBudgetTracker_HourRollover(t *testing.T) {
	tr := NewBudgetTracker()
	base := time.Now()
	tr.now = func() time.Time { return base }
	tr.Record("user:alice", 100, 0.01)

	tr.now = func() time.Time { return base.Add(61 * time.Minute) }
	u := tr.Snapshot("user:alice")
	if u.TokensLastHour != 0 {
		t.Fatalf("expected hour rollover, got %d", u.TokensLastHour)
	}
}

func TestBudgetTracker_SubjectIsolation(t *testing.T) {
	tr := NewBudgetTracker()
	now := time.Now()
	tr.now = func() time.Time { return now }
	tr.Record("user:alice", 100, 0.01)
	tr.Record("user:bob", 50, 0.005)

	a := tr.Snapshot("user:alice")
	b := tr.Snapshot("user:bob")
	if a.TokensLastMinute != 100 || b.TokensLastMinute != 50 {
		t.Fatalf("alice=%d bob=%d, want 100 and 50", a.TokensLastMinute, b.TokensLastMinute)
	}
}

// ---------------------------------------------------------------------------
// BudgetEnforcer — via real OPA engine
// ---------------------------------------------------------------------------

// setupBudgetOPA builds a temp policy dir with the real budget.rego and the
// provided data.budget payload. Uses the package's own policies/rego
// directory, copied verbatim, so the test reflects production policy.
func setupBudgetOPA(t *testing.T, budgetData map[string]interface{}) *policy.Engine {
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
		src, _ := os.ReadFile(filepath.Join(srcRegoDir, name))
		_ = os.WriteFile(filepath.Join(dir, name), src, 0o644)
	}

	data := map[string]interface{}{
		"config":            map[string]interface{}{"policy_name": "budget-test"},
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

	eng, err := policy.New(dir)
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	if err := eng.Compile(); err != nil {
		t.Fatalf("engine.Compile: %v", err)
	}
	return eng
}

func testBudgetData() map[string]interface{} {
	return map[string]interface{}{
		"subjects": map[string]interface{}{
			"default": map[string]interface{}{
				"tokens_per_minute":   1000,
				"tokens_per_hour":     10000,
				"tokens_per_day":      100000,
				"requests_per_minute": 10,
				"requests_per_hour":   100,
				"requests_per_day":    1000,
				"cost_per_hour":       1.0,
				"cost_per_day":        10.0,
			},
		},
		"pricing": map[string]interface{}{
			"default": map[string]float64{"input_per_1k": 0.001, "output_per_1k": 0.003},
			"gpt-4o":  map[string]float64{"input_per_1k": 0.0025, "output_per_1k": 0.010},
		},
	}
}

func TestBudgetEnforcer_DisabledAllowsAll(t *testing.T) {
	eng := setupBudgetOPA(t, testBudgetData())
	enf := NewBudgetEnforcer(config.BudgetConfig{Enabled: false}, eng)

	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	d := enf.Check(context.Background(), r, "gpt-4o", 100)
	if !d.Allowed {
		t.Fatalf("disabled enforcer should allow, got decision=%+v", d)
	}
}

func TestBudgetEnforcer_EnforceDenies(t *testing.T) {
	eng := setupBudgetOPA(t, testBudgetData())
	enf := NewBudgetEnforcer(config.BudgetConfig{
		Enabled: true,
		Mode:    "enforce",
	}, eng)

	// Pre-populate usage so the next request blows through tokens_per_minute.
	enf.tracker.Record("default", 950, 0)

	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	d := enf.Check(context.Background(), r, "gpt-4o", 100)
	if d.Allowed {
		t.Fatalf("expected deny, got allow (decision=%+v)", d)
	}
	if d.Rule != "tokens_per_minute" {
		t.Fatalf("expected rule tokens_per_minute, got %q", d.Rule)
	}
}

func TestBudgetEnforcer_MonitorDoesNotBlock(t *testing.T) {
	eng := setupBudgetOPA(t, testBudgetData())
	enf := NewBudgetEnforcer(config.BudgetConfig{
		Enabled: true,
		Mode:    "monitor",
	}, eng)

	enf.tracker.Record("default", 950, 0)

	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	d := enf.Check(context.Background(), r, "gpt-4o", 100)
	if !d.Allowed {
		t.Fatalf("monitor mode should allow, got %+v", d)
	}
	if !d.Monitor {
		t.Fatalf("expected Monitor=true in decision, got %+v", d)
	}
	if d.Rule != "tokens_per_minute" {
		t.Fatalf("expected rule tokens_per_minute, got %q", d.Rule)
	}
}

func TestBudgetEnforcer_SubjectHeader(t *testing.T) {
	data := testBudgetData()
	data["subjects"].(map[string]interface{})["user:strict"] = map[string]interface{}{
		"tokens_per_minute":   10,
		"tokens_per_hour":     100,
		"tokens_per_day":      1000,
		"requests_per_minute": 1,
		"requests_per_hour":   10,
		"requests_per_day":    100,
		"cost_per_hour":       0.01,
		"cost_per_day":        0.10,
	}
	eng := setupBudgetOPA(t, data)
	enf := NewBudgetEnforcer(config.BudgetConfig{
		Enabled:       true,
		Mode:          "enforce",
		SubjectHeader: "X-DC-Subject",
	}, eng)

	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.Header.Set("X-DC-Subject", "user:strict")
	d := enf.Check(context.Background(), r, "gpt-4o", 50)
	if d.Allowed {
		t.Fatalf("expected deny for user:strict with 50 tokens > limit 10, got allow (decision=%+v)", d)
	}
	if d.Subject != "user:strict" {
		t.Fatalf("expected subject user:strict, got %q", d.Subject)
	}
}

func TestBudgetEnforcer_RecordUpdatesCounters(t *testing.T) {
	eng := setupBudgetOPA(t, testBudgetData())
	enf := NewBudgetEnforcer(config.BudgetConfig{
		Enabled: true,
		Mode:    "enforce",
	}, eng)

	enf.Record("user:alice", "gpt-4o", 200, 100)
	u := enf.tracker.Snapshot("user:alice")
	if u.TokensLastMinute != 300 {
		t.Fatalf("tokens_last_minute=%d, want 300", u.TokensLastMinute)
	}
	if u.RequestsLastMinute != 1 {
		t.Fatalf("requests_last_minute=%d, want 1", u.RequestsLastMinute)
	}
}

// ---------------------------------------------------------------------------
// PricingTable
// ---------------------------------------------------------------------------

func TestPricingTable_EstimateCost_Known(t *testing.T) {
	eng := setupBudgetOPA(t, testBudgetData())
	p := NewPricingTable(eng)

	cost := p.EstimateCost("gpt-4o", 1000, 1000)
	// 1k prompt @ $0.0025 + 1k completion @ $0.010 = $0.0125
	if cost < 0.0124 || cost > 0.0126 {
		t.Fatalf("expected ~$0.0125, got $%f", cost)
	}
}

func TestPricingTable_EstimateCost_Default(t *testing.T) {
	eng := setupBudgetOPA(t, testBudgetData())
	p := NewPricingTable(eng)

	cost := p.EstimateCost("unknown-model", 1000, 1000)
	// 1k @ $0.001 + 1k @ $0.003 = $0.004
	if cost < 0.0039 || cost > 0.0041 {
		t.Fatalf("expected ~$0.004, got $%f", cost)
	}
}

func TestEstimateRequestTokens(t *testing.T) {
	max := 2048
	req := &ChatRequest{
		Model: "gpt-4o",
		Messages: []ChatMessage{
			{Role: "user", Content: "hello world"}, // 11 bytes → ~2 tokens
		},
		MaxTokens: &max,
	}
	est := estimateRequestTokens(req)
	if est < int64(max) {
		t.Fatalf("estimate %d should be at least %d", est, max)
	}
	if est > int64(max)+10 {
		t.Fatalf("estimate %d is unreasonably high (max=%d)", est, max)
	}
}
