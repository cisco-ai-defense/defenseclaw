// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// newFloorTestServer is a codex hook-lane judge (cascade 3) whose LLM
// judge answers after delay, with a decision model that gives a confident
// block (risk 0.98, risk score 1.96).
func newFloorTestServer(t *testing.T, delay time.Duration) (*APIServer, *slowLLMProvider) {
	t.Helper()
	srv := fakeDecisionModel(t, "block", 0.02, nil)
	t.Cleanup(srv.Close)
	p := &slowLLMProvider{
		mockLLMProvider: mockLLMProvider{response: injectionHitProvider().response},
		delay:           delay,
		finished:        make(chan error, 8),
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Judge = config.JudgeConfig{Enabled: true, Injection: true, ToolInjection: true, HookConnectors: []string{"codex"}}
	cfg.Guardrail.DetectionStrategy = "judge_first"
	a := &APIServer{scannerCfg: cfg}
	a.SetHookJudge(&LLMJudge{cfg: &cfg.Guardrail.Judge, model: "test-model", provider: p, rp: &guardrail.RulePack{},
		decision: testDecisionModel(t, srv.URL, "")})
	return a, p
}

// TestDecisionFloorSurvivesALateJudge (GAP-0392): in cascade 3 a System One
// confident block reaches the judge; when the judge misses the hook answer
// window the hook answers with the decision-model floor, not with nothing.
func TestDecisionFloorSurvivesALateJudge(t *testing.T) {
	a, p := newFloorTestServer(t, 5*time.Second)
	// The hook reached the gateway 2.6 s ago: 0.8 s of the 3.4 s window left,
	// enough for the decision model, not for the 5 s judge.
	ctx := boundedHookContext(time.Now().Add(-2600 * time.Millisecond))
	t0 := time.Now()
	v := a.runHookJudge(ctx, "tool_call", "tool_call", "codex", `{"command":"go test ./internal/... -run TestSomething -count=1 -v"}`, "Bash", nil)
	if elapsed := time.Since(t0); elapsed > 2*time.Second {
		t.Fatalf("the hook held the answer %s past its window", elapsed)
	}
	if v == nil || v.Severity != "HIGH" || !hasFinding(v.Findings, decisionModelFindingID) {
		t.Fatalf("late judge: verdict = %+v, want the HIGH decision-model floor", v)
	}
	select {
	case <-p.finished:
	case <-time.After(10 * time.Second):
		t.Fatal("the late judge never finished")
	}
}

// TestDecisionFloorAbsentWithoutABlock: with no decision-model block the
// late path keeps the rule verdict (nil), as before.
func TestDecisionFloorAbsentWithoutABlock(t *testing.T) {
	slot := &decisionFloorSlot{}
	if slot.get() != nil {
		t.Fatal("empty slot returned a floor")
	}
	var none *decisionFloorSlot
	none.set(&ScanVerdict{Severity: "HIGH"})
	if none.get() != nil {
		t.Fatal("nil slot returned a floor")
	}
	ctx := withDecisionFloorSlot(context.Background(), slot)
	decisionFloorSlotFrom(ctx).set(&ScanVerdict{Severity: "HIGH", Findings: []string{decisionModelFindingID}})
	got := slot.get()
	if got == nil || got.Severity != "HIGH" {
		t.Fatalf("slot = %+v", got)
	}
	got.Severity = "LOW" // a copy: the caller cannot lower the stored floor
	if slot.get().Severity != "HIGH" {
		t.Fatal("the stored floor was changed through a returned copy")
	}
}
