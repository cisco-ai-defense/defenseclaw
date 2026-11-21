// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Two judge generations that hold the same session (a config or rule-pack
// reload while calls run on the old one) write its target history under one
// lock: the successor takes over the table (inheritToolJudgeContext), and a
// call never writes a map another call reads (rel-1-0-10:GAP-0635). Under
// -race a map written by two judges is a reported race; in the plain build it
// was "fatal error: concurrent map read and map write".
func TestJudgeGenerationsShareNoSessionTargets(t *testing.T) {
	ctx := ContextWithSessionID(context.Background(), "gen-carry-1")
	oldJ, newJ := judgePacketTestJudge(), judgePacketTestJudge()
	oldJ.ObserveSessionPrompt(ctx, "tidy the docs folder")
	oldJ.toolJudgeContextSample(ctx, "Bash", `{"command":"cat /repo/docs/a.md"}`)
	newJ.inheritToolJudgeContext(oldJ)

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
	if !newT["/repo/docs/a.md"] {
		t.Fatal("the carried read is lost on the new judge")
	}
	// One session, one history: every call of both generations is in it.
	if len(oldT) != 101 || len(newT) != 101 {
		t.Fatalf("history holds %d (old) and %d (new) targets, want 101 in both", len(oldT), len(newT))
	}
}

// recordJudgeTargets never writes the history it is given.
func TestRecordJudgeTargetsIsCopyOnWrite(t *testing.T) {
	history := map[string]judgeTargetSeen{"/a": {ordinal: 1, accesses: make([]string, 1, 4)}}
	history["/a"].accesses[0] = "read"
	effects := judgeCallEffects{modeled: true, targets: []judgeTarget{{access: "write", path: "/a"}, {access: "read", path: "/b"}}}
	body, next := recordJudgeTargets(history, 2, effects)
	if len(history) != 1 || !slices.Equal(history["/a"].accesses, []string{"read"}) || history["/a"].ordinal != 1 {
		t.Fatalf("input history changed: %+v", history)
	}
	if spare := history["/a"].accesses[:2]; spare[1] != "" {
		t.Fatalf("the new access was written into the old slice's spare capacity: %q", spare)
	}
	if !slices.Equal(next["/a"].accesses, []string{"read", "write"}) || next["/b"].ordinal != 2 {
		t.Fatalf("new history: %+v", next)
	}
	if body != "/a: read (call 1 of this session)" {
		t.Fatalf("target history body: %q", body)
	}
}

// The tool-result sections carry no credentials from the call's arguments
// (rel-1-0-10:GAP-0638).
func TestToolResultJudgeCallIsRedacted(t *testing.T) {
	j := newMockJudge(t, &mockLLMProvider{})
	args, _ := json.Marshal(map[string]any{
		"url":     "https://svc-user:Pw0rdValue123@api.example.com/v1/items?api_key=AbCdEf0123456789",
		"headers": map[string]string{"Authorization": "Bearer tok_AbCdEf0123456789xyz"},
	})
	ctx := withToolResultCall(context.Background(), "fetch_items", json.RawMessage(args))
	header := j.toolResultJudgeSections(ctx, "message").sections
	for _, secret := range []string{"Pw0rdValue123", "AbCdEf0123456789", "tok_AbCdEf0123456789xyz"} {
		if strings.Contains(header, secret) {
			t.Errorf("header carries %q:\n%s", secret, header)
		}
	}
	if !strings.Contains(header, "api.example.com") {
		t.Errorf("redaction removed the endpoint:\n%s", header)
	}
	// The user's request (on Hermes and OpenClaw possibly a remote party's
	// text) is redacted the same way and never reaches the system message.
	sctx := ContextWithSessionID(context.Background(), "tr-redact-1")
	j.ObserveSessionPrompt(sctx, "fetch the items, the token is Bearer tok_ZyXwVu9876543210abc")
	sctx = withToolResultCall(sctx, "fetch_items", json.RawMessage(args))
	tc := j.toolResultJudgeSections(sctx, "message")
	if strings.Contains(tc.sections, "tok_ZyXwVu9876543210abc") || !strings.Contains(tc.sections, "fetch the items") {
		t.Errorf("user request section not redacted: %q", tc.sections)
	}
	if strings.Contains(tc.system, "fetch the items") || strings.Contains(tc.system, "api.example.com") {
		t.Errorf("session text reached the system note: %q", tc.system)
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

// With the lane off the tool-result judges judge the output alone, on the
// completion route and on the tool_result route (injection judge) alike,
// with or without a recorded call (rel-1-0-10:GAP-0847).
func TestToolResultContextLaneOff(t *testing.T) {
	mock := &mockLLMProvider{response: &ChatResponse{Choices: []ChatChoice{{Message: &ChatMessage{Role: "assistant", Content: cleanInjectionJudgeJSON}}}}}
	j := newMockJudge(t, mock)
	j.cfg.Injection, j.cfg.PII, j.cfg.PIICompletion = true, true, true
	sctx := ContextWithSessionID(context.Background(), "tr-off-1")
	j.ObserveSessionPrompt(sctx, "list my team")
	for name, run := range map[string]func(){
		"completion with call": func() {
			j.RunJudges(withoutToolResultCall(withToolResultCall(sctx, "users_list", map[string]any{"q": "team"})), "completion", "alice@example.com, bob@example.org", "message")
		},
		"tool_result with call": func() {
			j.RunJudges(withoutToolResultCall(withToolResultCall(sctx, "users_list", map[string]any{"q": "team"})), directionToolResult, "the team page lists alice and bob", "users_list")
		},
		"tool_result without call": func() {
			j.RunJudges(withoutToolResultCall(sctx), directionToolResult, "the team page lists alice and bob", "users_list")
		},
	} {
		mock.captured = nil
		run()
		if len(mock.captured) == 0 {
			t.Fatalf("%s: no judge call", name)
		}
		for _, req := range mock.captured {
			for _, m := range req.Messages {
				if strings.Contains(m.Content, "CONTEXT FROM DEFENSECLAW") || strings.Contains(m.Content, "SESSION_USER_INTENT") || strings.Contains(m.Content, "CURRENT_TOOL_CALL") {
					t.Fatalf("%s: lane off still sends the tool-result context: %.300q", name, m.Content)
				}
			}
		}
	}
}

// An empty judge answer (rel-1-0-10:GAP-0610 class: Gemma 4 sometimes returns no
// content) is a judge failure: the hook keeps the rule verdict, and the
// cascade's judge.no_verdict decides whether that is the unknown tier. It is
// never read as an allow.
func TestToolJudgeEmptyAnswerFallsBackToTheRules(t *testing.T) {
	for _, content := range []string{"", "   ", "not json"} {
		mock := &mockLLMProvider{response: &ChatResponse{Choices: []ChatChoice{{Message: &ChatMessage{Role: "assistant", Content: content}}}}}
		j := newMockJudge(t, mock)
		j.cfg.ToolInjection = true
		v := j.RunToolJudge(context.Background(), "Bash", `{"command":"make build"}`)
		if v == nil || !v.JudgeFailed {
			t.Fatalf("answer %q: verdict %+v, want a judge failure", content, v)
		}
		cfg := config.DefaultConfig()
		cfg.DataDir = t.TempDir()
		if lane := hookJudgeLaneVerdict(cfg, "claudecode", "tool_call", v); lane != nil {
			t.Fatalf("answer %q: the hook lane took %+v, want the rule verdict kept", content, lane)
		}
	}
}

// The cascade merge trap (rel-1-0-10:GAP-0636 (a)): the proven-read skip
// answers before guardrail.cascade.judge.no_verdict, so with no_verdict
// unknown a proven read the rules did not flag stays an allow and is not sent
// to the judge, in every pack; a call that is not a proven read still goes to
// the judge.
func TestProvenReadSkipBeforeCascadeNoVerdict(t *testing.T) {
	for _, pack := range []string{"default", "strict"} {
		judge := &mockLLMProvider{response: &ChatResponse{Choices: []ChatChoice{{Message: &ChatMessage{Content: reviewOnlyJudgeMedium}}}}}
		a := escalationHookServerWith(t, judge, pack, func(cfg *config.Config) {
			cfg.Guardrail.Cascade.Judge.NoVerdict = config.CascadeNoVerdictUnknown
		})
		home := t.TempDir()
		resp := a.evaluateClaudeCodeHook(t.Context(), claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: "s-pr-skip-" + pack, CWD: home, ToolName: "Read",
			ToolInput: map[string]interface{}{"file_path": filepath.Join(home, "README.md")},
		})
		if len(judge.captured) != 0 || resp.RawAction != "allow" {
			t.Fatalf("%s: proven read: judge calls=%d raw=%q findings=%v, want allow with no judge call", pack, len(judge.captured), resp.RawAction, resp.Findings)
		}
		a.evaluateClaudeCodeHook(t.Context(), claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: "s-pr-skip-" + pack, CWD: home, ToolName: "Bash",
			ToolInput: map[string]interface{}{"command": "make -C ./fixtures build"},
		})
		if len(judge.captured) != 1 {
			t.Fatalf("%s: a call that is not a proven read was not judged (calls=%d)", pack, len(judge.captured))
		}
	}
}
