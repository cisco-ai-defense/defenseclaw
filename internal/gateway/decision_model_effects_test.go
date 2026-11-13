// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestDecisionCallEffectsProjection(t *testing.T) {
	ce := computeDecisionCallEffects("Bash", `{"command":"go test ./... > out.txt"}`)
	if ce.V != 1 || ce.Truncated {
		t.Fatalf("call_effects = %+v", ce)
	}
	kinds := map[string]bool{}
	for _, e := range ce.Effects {
		kinds[e.Kind] = true
	}
	if !kinds["exec"] || !kinds["write"] {
		t.Fatalf("effects of a redirect = %+v", ce.Effects)
	}
	again := computeDecisionCallEffects("Bash", `{"command":"go test ./... > out.txt"}`)
	a, _ := json.Marshal(ce)
	b, _ := json.Marshal(again)
	if string(a) != string(b) {
		t.Fatalf("projection is not deterministic:\n%s\n%s", a, b)
	}
	// A non-JSON argument string is read as a command, not dropped.
	if raw := computeDecisionCallEffects("Bash", "ls -la"); raw == nil || raw.Truncated {
		t.Fatalf("plain-string argument = %+v", raw)
	}
}

// TestDecisionCallEffectsCapTruncates: past the effect cap the projection is
// TRUNCATED and keeps what it saw, and a confident allow on it is not
// trusted (ONE BOUND RULE).
func TestDecisionCallEffectsCapTruncates(t *testing.T) {
	files := make([]string, maxDecisionCallEffects+8)
	for i := range files {
		files[i] = fmt.Sprintf("f%02d.txt", i)
	}
	args, _ := json.Marshal(map[string]string{"command": "touch " + strings.Join(files, " ")})
	ce := computeDecisionCallEffects("Bash", string(args))
	if !ce.Truncated || len(ce.Effects) != maxDecisionCallEffects || !strings.Contains(strings.Join(ce.Caps, ","), "effects") {
		t.Fatalf("over the cap: truncated=%v effects=%d caps=%v", ce.Truncated, len(ce.Effects), ce.Caps)
	}

	srv := fakeDecisionModel(t, "allow", 0.99, nil)
	defer srv.Close()
	dm := testDecisionModel(t, srv.URL, "")
	if got := dm.decide(context.Background(), decisionModelState{CallEffects: ce}); got.route != decisionEscalate {
		t.Fatalf("confident allow on truncated effects: route %v, want escalate", got.route)
	}
	if got := dm.decide(context.Background(), decisionModelState{CallEffects: computeDecisionCallEffects("Bash", `{"command":"ls"}`)}); got.route != decisionAllow {
		t.Fatalf("confident allow on complete effects: route %v, want allow", got.route)
	}
}

// TestDecisionCallEffectsOnlyWhenSent: off by default (the request is
// unchanged), on adds a versioned call_effects, and a paused model costs no
// extraction.
func TestDecisionCallEffectsOnlyWhenSent(t *testing.T) {
	var seen atomic.Value
	srv := fakeDecisionModel(t, "allow", 0.99, &seen)
	defer srv.Close()
	j := &LLMJudge{cfg: &config.JudgeConfig{ToolInjection: true}}
	off := testDecisionModel(t, srv.URL, "")
	j.decision = off
	j.runToolDecision(context.Background(), "Bash", `{"command":"go build ./..."}`, "s1")
	if body, _ := seen.Load().(string); strings.Contains(body, "call_effects") {
		t.Fatalf("call_effects sent while off: %s", body)
	}

	on := testDecisionModel(t, srv.URL, "")
	on.callEffects = true
	j.decision = on
	j.runToolDecision(context.Background(), "Bash", `{"command":"go build ./..."}`, "s2")
	body, _ := seen.Load().(string)
	if !strings.Contains(body, `"call_effects":{"v":1,"effects":[`) {
		t.Fatalf("call_effects missing: %s", body)
	}

	on.breakerMu.Lock()
	on.openUntil = time.Now().Add(time.Minute)
	on.breakerMu.Unlock()
	if st := on.withCallEffects(context.Background(), decisionModelState{}, "Bash", `{"command":"ls"}`); st.CallEffects != nil {
		t.Fatal("call_effects computed for a call that will not be sent")
	}
}

func TestDecisionCallEffectsConfig(t *testing.T) {
	good := "config_version: 9\ndecision_model:\n  call_effects: true\n"
	if err := config.ValidateV8SchemaBytes("config.yaml", []byte(good)); err != nil {
		t.Fatalf("schema refused call_effects: %v", err)
	}
	cfg := &config.Config{DecisionModel: config.DecisionModelConfig{Enabled: true, Model: "m", BaseURL: "http://127.0.0.1:1/x", CallEffects: true}}
	if dm := newDecisionModel(cfg, ""); dm == nil || !dm.callEffects {
		t.Fatal("decision_model.call_effects not applied")
	}
}
