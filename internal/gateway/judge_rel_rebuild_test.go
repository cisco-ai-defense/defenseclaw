// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Two judge generations that hold the same session (a config or rule-pack
// reload while calls run on the old one) never share its target history: a
// call on either one writes a new map (rel-1-0-10:GAP-0635). Under -race a
// shared map is a reported race; in the plain build it was "fatal error:
// concurrent map read and map write".
func TestJudgeGenerationsShareNoSessionTargets(t *testing.T) {
	ctx := ContextWithSessionID(context.Background(), "gen-carry-1")
	oldJ, newJ := judgePacketTestJudge(), judgePacketTestJudge()
	oldJ.ObserveSessionPrompt(ctx, "tidy the docs folder")
	oldJ.toolJudgeContextSample(ctx, "Bash", `{"command":"cat /repo/docs/a.md"}`)
	carrySessionForTest(ctx, oldJ, newJ)

	var wg sync.WaitGroup
	for g, j := range []*LLMJudge{oldJ, newJ} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 50 { // 1 + 2 x 50 targets stay under maxJudgeTargetHistory
				j.toolJudgeContextSample(ctx, "Bash", fmt.Sprintf(`{"command":"cat /repo/docs/g%d-%d.md"}`, g, i))
			}
		}()
	}
	wg.Wait()

	oldT, newT := sessionTargetsForTest(ctx, oldJ), sessionTargetsForTest(ctx, newJ)
	if !oldT["/repo/docs/a.md"] || !newT["/repo/docs/a.md"] {
		t.Fatalf("the carried read is lost: old=%v new=%v", oldT["/repo/docs/a.md"], newT["/repo/docs/a.md"])
	}
	for path := range newT {
		if strings.Contains(path, "/g1-") && oldT[path] {
			t.Fatalf("a call on the new judge wrote the old judge's history: %s", path)
		}
	}
	for path := range oldT {
		if strings.Contains(path, "/g0-") && newT[path] {
			t.Fatalf("a call on the old judge wrote the new judge's history: %s", path)
		}
	}
}

// recordJudgeTargets never writes the history it is given.
func TestRecordJudgeTargetsIsCopyOnWrite(t *testing.T) {
	history := map[string]judgeTargetSeen{"/a": {ordinal: 1, accesses: make([]string, 1, 4)}}
	history["/a"].accesses[0] = "read"
	effects := judgeCallEffects{modeled: true, targets: []judgeTarget{{access: "write", path: "/a"}, {access: "read", path: "/b"}}}
	var b strings.Builder
	next := recordJudgeTargets(&b, history, 2, effects)
	if len(history) != 1 || !slices.Equal(history["/a"].accesses, []string{"read"}) || history["/a"].ordinal != 1 {
		t.Fatalf("input history changed: %+v", history)
	}
	if spare := history["/a"].accesses[:2]; spare[1] != "" {
		t.Fatalf("the new access was written into the old slice's spare capacity: %q", spare)
	}
	if !slices.Equal(next["/a"].accesses, []string{"read", "write"}) || next["/b"].ordinal != 2 {
		t.Fatalf("new history: %+v", next)
	}
	if !strings.Contains(b.String(), "/a: read (call 1 of this session)") {
		t.Fatalf("target history block: %q", b.String())
	}
}

// The call line of the tool-result header carries no credentials from the
// call's arguments (rel-1-0-10:GAP-0638).
func TestToolResultJudgeCallIsRedacted(t *testing.T) {
	j := newMockJudge(t, &mockLLMProvider{})
	args, _ := json.Marshal(map[string]any{
		"url":     "https://svc-user:Pw0rdValue123@api.example.com/v1/items?api_key=AbCdEf0123456789",
		"headers": map[string]string{"Authorization": "Bearer tok_AbCdEf0123456789xyz"},
	})
	ctx := withToolResultCall(context.Background(), "fetch_items", json.RawMessage(args))
	header := j.toolResultJudgeHeader(ctx, "message")
	for _, secret := range []string{"Pw0rdValue123", "AbCdEf0123456789", "tok_AbCdEf0123456789xyz"} {
		if strings.Contains(header, secret) {
			t.Errorf("header carries %q:\n%s", secret, header)
		}
	}
	if !strings.Contains(header, "api.example.com") {
		t.Errorf("redaction removed the endpoint:\n%s", header)
	}
}

// The parser runs once for the skip, the packet and the review-only check of
// one judged call (rel-1-0-10:GAP-0642); another call parses on its own.
func TestJudgeFactsMemoParsesACallOnce(t *testing.T) {
	ctx := withJudgeFactsMemo(context.Background())
	args := `{"command":"cat README.md"}`
	_ = hookJudgeSkipsProvenReadOnly(ctx, "Bash", args, nil)
	memo := ctx.Value(judgeFactsMemoKey{}).(*judgeFactsMemo)
	first := memo.key
	if !memo.set || first == "" {
		t.Fatal("the skip did not fill the memo")
	}
	effects := toolJudgeCallEffects(ctx, "Bash", args)
	if memo.key != first || !effects.modeled {
		t.Fatalf("the packet parsed another input (%q) or lost the effects", memo.key)
	}
	_ = toolJudgeCallEffects(ctx, "Bash", `{"command":"ls docs"}`)
	if memo.key == first {
		t.Fatal("a different call reused the memo")
	}
	if got, want := toolJudgeCallEffects(context.Background(), "Bash", args), effects; got.modeled != want.modeled || !slices.Equal(got.programs, want.programs) {
		t.Fatalf("memoized effects differ from a fresh parse: %+v vs %+v", want, got)
	}
}

// The judge's stages are registered cascade lanes, on by default, settable
// per connector (rel-1-0-10:GAP-0636).
func TestJudgeStagesAreCascadeLanes(t *testing.T) {
	names := config.CascadeLaneNames()
	for _, lane := range []string{config.CascadeLaneJudgeReadSkip, config.CascadeLaneJudgeUnmodeledAlert, config.CascadeLaneJudgeToolResultContext} {
		if !slices.Contains(names, lane) {
			t.Fatalf("lane %s is not registered: %v", lane, names)
		}
		if !judgeLaneOn(nil, "claudecode", lane) || !judgeLaneOn(config.DefaultConfig(), "claudecode", lane) {
			t.Fatalf("lane %s is not on by default", lane)
		}
	}
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.Guardrail.Cascade.SetLane(config.CascadeLaneJudgeUnmodeledAlert, config.CascadeLaneOff)
	if reviewOnlyUnmodeledAlerts(cfg, "claudecode") {
		t.Fatal("judge_unmodeled_alert off still alerts")
	}
	cfg.Guardrail.Cascade.SetLane(config.CascadeLaneJudgeUnmodeledAlert, config.CascadeLaneShadow)
	if reviewOnlyUnmodeledAlerts(cfg, "claudecode") {
		t.Fatal("judge_unmodeled_alert shadow must act as off")
	}
	lone := toolInjectionToVerdict(parseJudgeJSON(reviewOnlyJudgeMedium))
	lane := judgeReviewOnlyAudit(cfg, "claudecode", false, false, hookJudgeLaneVerdict(cfg, "claudecode", "tool_call", lone))
	if lane == nil || lane.Action != guardrailActionAllow {
		t.Fatalf("lane off: an unmodeled lone review finding should be audit-only, got %+v", lane)
	}
}

// With the lane off the tool-result judges judge the output alone.
func TestToolResultContextLaneOff(t *testing.T) {
	mock := &mockLLMProvider{response: &ChatResponse{Choices: []ChatChoice{{Message: &ChatMessage{Role: "assistant", Content: cleanInjectionJudgeJSON}}}}}
	j := newMockJudge(t, mock)
	j.cfg.PII, j.cfg.PIICompletion = true, true
	ctx := withoutToolResultCall(withToolResultCall(context.Background(), "users_list", map[string]any{"q": "team"}))
	j.RunJudges(ctx, "completion", "alice@example.com, bob@example.org", "message")
	for _, req := range mock.captured {
		for _, m := range req.Messages {
			if strings.Contains(m.Content, "CONTEXT FROM DEFENSECLAW") || strings.Contains(m.Content, "USER_REQUEST") {
				t.Fatalf("lane off still sends the tool-result context: %q", m.Content)
			}
		}
	}
}
