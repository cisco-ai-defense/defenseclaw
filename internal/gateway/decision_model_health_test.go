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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestHealthSnapshotShowsADeadDecisionModel pins GAP-0604: a dead decision
// model (System One) endpoint still fails open (the rule verdict stands), and
// its failed calls now show in the guardrail health as decision_model_*
// details, so doctor and status can name it. They are not LLM judge failures.
func TestHealthSnapshotShowsADeadDecisionModel(t *testing.T) {
	h := NewSidecarHealth()
	t.Cleanup(func() { NewSidecarHealth() }) // resets the health windows
	h.SetGuardrail(StateRunning, "", map[string]interface{}{"mode": "action"})

	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	cfg := &config.Config{DataDir: t.TempDir()}
	cfg.DecisionModel = config.DecisionModelConfig{Enabled: true, Model: "fake", BaseURL: deadURL, Timeout: 0.5,
		HookConnectors: []string{"claudecode"}}
	j := newDecisionOnlyJudge(cfg)
	if j == nil {
		t.Fatal("newDecisionOnlyJudge returned nil")
	}
	// Fewer calls than the breaker trips on, so every call reaches the model.
	for i := 0; i < decisionBreakerFailures-1; i++ {
		v := j.RunToolJudge(context.Background(), "Bash", `{"command":"ls -la"}`)
		if v == nil || !v.JudgeFailed || v.Action != guardrailActionAllow {
			t.Fatalf("call %d gave %+v, want the fail-open verdict (judge failed, allow)", i, v)
		}
		if lane := hookJudgeLaneVerdict(cfg, "claudecode", "tool_call", v); lane != nil {
			t.Fatalf("call %d reached the hook lane as %+v, want nil (the rule verdict stands)", i, lane)
		}
	}
	want := decisionBreakerFailures - 1
	d := h.Snapshot().Guardrail.Details
	if d["decision_model_state"] != "failing" || d["decision_model_failed_calls"] != want ||
		d["decision_model_recent_calls"] != want || d["mode"] != "action" {
		t.Fatalf("details = %v, want a failing decision model with %d failed calls", d, want)
	}
	if e, _ := d["decision_model_last_error"].(string); e == "" {
		t.Fatalf("details = %v, want the last decision-model error", d)
	}
	if _, ok := d["judge_state"]; ok {
		t.Fatalf("details = %v: a decision-model outage is not an LLM judge outage", d)
	}

	up := fakeDecisionModel(t, "allow", 0.95, nil)
	defer up.Close()
	cfg.DecisionModel.BaseURL = up.URL
	if v := newDecisionOnlyJudge(cfg).RunToolJudge(context.Background(), "Bash", `{"command":"ls -la"}`); v == nil || v.JudgeFailed {
		t.Fatalf("a live model gave %+v, want an answer", v)
	}
	if d := h.Snapshot().Guardrail.Details; d["decision_model_state"] != "degraded" || d["decision_model_recent_calls"] != want+1 {
		t.Fatalf("details after a good call = %v, want degraded", d)
	}
}
