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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// TestHealthSnapshotShowsFailingJudge pins GAP-1120/GAP-1288: judge calls
// that fail show in the guardrail health details, so status can say so.
func TestHealthSnapshotShowsFailingJudge(t *testing.T) {
	h := NewSidecarHealth()
	t.Cleanup(judgeHealth.reset)
	h.SetGuardrail(StateRunning, "", map[string]interface{}{"mode": "action"})
	if _, ok := h.Snapshot().Guardrail.Details["judge_state"]; ok {
		t.Fatal("judge details before any judge call")
	}
	for i := 0; i < 3; i++ {
		emitJudge(context.Background(), "pii", "m", gatewaylog.DirectionPrompt, 1, 1, "error",
			gatewaylog.SeverityHigh, "failed to retrieve aws credentials", "",
			JudgeEmitOpts{FailureClass: gatewaylog.JudgeFailureProvider})
	}
	d := h.Snapshot().Guardrail.Details
	if d["judge_state"] != "failing" || d["judge_failed_calls"] != 3 ||
		d["judge_last_error"] != "failed to retrieve aws credentials" || d["mode"] != "action" {
		t.Fatalf("details = %v", d)
	}
	emitJudge(context.Background(), "pii", "m", gatewaylog.DirectionPrompt, 1, 1, "allow",
		gatewaylog.SeverityInfo, "", "", JudgeEmitOpts{})
	if d := h.Snapshot().Guardrail.Details; d["judge_state"] != "degraded" || d["judge_recent_calls"] != 4 {
		t.Fatalf("details after a good call = %v", d)
	}
}

// GAP-0383: an enabled judge whose LLM has no key is reported as not
// running, and the calls of the judge it replaced no longer read as working.
func TestHealthSnapshotShowsAJudgeThatCouldNotStart(t *testing.T) {
	h := NewSidecarHealth()
	t.Cleanup(judgeHealth.reset)
	t.Setenv("JUDGE_HEALTH_TEST_KEY", "")
	emitJudge(context.Background(), "pii", "m", gatewaylog.DirectionPrompt, 1, 1, "allow",
		gatewaylog.SeverityInfo, "", "", JudgeEmitOpts{})

	judge, reason := newLLMJudgeWithReason(
		&config.JudgeConfig{Enabled: true},
		config.LLMConfig{Provider: "openai", Model: "gpt-judge-x", APIKeyEnv: "JUDGE_HEALTH_TEST_KEY"},
		"", nil, nil,
	)
	if judge != nil || !strings.Contains(reason, "JUDGE_HEALTH_TEST_KEY") {
		t.Fatalf("judge=%v reason=%q, want no judge and a reason naming the key", judge, reason)
	}
	judgeHealth.applyJudge(judge, reason)
	d := h.Snapshot().Guardrail.Details
	if d["judge_state"] != "unavailable" || d["judge_unavailable_reason"] != reason || d["judge_recent_calls"] != nil {
		t.Fatalf("details = %v", d)
	}
	judgeHealth.applyJudge(&LLMJudge{}, "")
	if _, ok := h.Snapshot().Guardrail.Details["judge_state"]; ok {
		t.Fatal("a running judge still reads as unavailable")
	}
}
