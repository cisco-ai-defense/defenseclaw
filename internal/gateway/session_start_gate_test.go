// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSessionStartGateHoldsCallsForTheStartVerdict(t *testing.T) {
	var gate sessionStartGate
	ctx := t.Context()
	if reason, refuse := gate.await(ctx, "codex\x00\x00unknown", time.Millisecond, 0, nil); refuse {
		t.Fatalf("a session without a recorded start was refused: %s", reason)
	}

	allowed := gate.begin("allowed")
	go func() {
		time.Sleep(50 * time.Millisecond)
		allowed.finish(false, "")
	}()
	if reason, refuse := gate.await(ctx, "allowed", 5*time.Second, 0, nil); refuse {
		t.Fatalf("a call did not wait for its allowed start: %s", reason)
	}

	pending := gate.begin("pending")
	if reason, refuse := gate.await(ctx, "pending", 20*time.Millisecond, 0, nil); !refuse || reason != sessionStartPendingReason {
		t.Fatalf("a call ran while its start was still judged: refuse=%t reason=%q", refuse, reason)
	}
	pending.finish(true, "unapproved hook ~/.claude/settings.json")
	reason, refuse := gate.await(ctx, "pending", time.Millisecond, 0, nil)
	if !refuse || !strings.Contains(reason, "unapproved hook") {
		t.Fatalf("a blocked start did not block its session: refuse=%t reason=%q", refuse, reason)
	}
	// Only the first verdict counts.
	pending.finish(false, "")
	if _, refuse := gate.await(ctx, "pending", time.Millisecond, 0, nil); !refuse {
		t.Fatal("a second finish replaced the start verdict")
	}
	// Starting the session again replaces the block.
	gate.begin("pending").finish(false, "")
	if reason, refuse := gate.await(ctx, "pending", time.Millisecond, 0, nil); refuse {
		t.Fatalf("a new allowed start kept the old block: %s", reason)
	}

	// A start being judged is never evicted, however many blocks fill the gate.
	held := gate.begin("held")
	for i := range sessionStartGateLimit + 8 {
		gate.begin("blocked-"+strconv.Itoa(i)).finish(true, "x")
	}
	if _, refuse := gate.await(ctx, "held", time.Millisecond, 0, nil); !refuse {
		t.Fatal("eviction dropped a pending session start")
	}
	held.finish(false, "")
}

type sessionStartGateHarness struct {
	t       *testing.T
	api     *APIServer
	handler http.HandlerFunc
	repair  chan error
	started chan struct{}
}

func newSessionStartGateHarness(t *testing.T) *sessionStartGateHarness {
	t.Helper()
	api := instructionProtectionTestAPI(t, "codex", "action", "HIGH")
	api.scannerCfg.DataDir = t.TempDir()
	h := &sessionStartGateHarness{t: t, api: api, repair: make(chan error), started: make(chan struct{}, 8)}
	api.SetHookRegistrationRepair(func(ctx context.Context, _ string) error {
		h.started <- struct{}{}
		select {
		case err := <-h.repair:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	h.handler = api.handleUnifiedConnectorHook("codex")
	return h
}

func (h *sessionStartGateHarness) post(event, session string, extra map[string]interface{}) (int, map[string]interface{}) {
	h.t.Helper()
	body := map[string]interface{}{"hook_event_name": event, "session_id": session}
	for key, value := range extra {
		body[key] = value
	}
	raw, err := json.Marshal(body)
	if err != nil {
		h.t.Error(err)
		return 0, nil
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", strings.NewReader(string(raw)))
	req.Header.Set("X-DefenseClaw-Hook-Event", event)
	req.Header.Set("X-DefenseClaw-Hook-Contract", h.api.hookProfileForConnector("codex").ContractID)
	rec := httptest.NewRecorder()
	h.handler(rec, req.WithContext(withAuthenticatedHookConnector(context.Background(), "codex")))
	var out map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (h *sessionStartGateHarness) toolCall(session string) (string, []string) {
	h.t.Helper()
	code, out := h.post("PreToolUse", session, map[string]interface{}{
		"tool_name": "Bash", "tool_input": map[string]interface{}{"command": "echo ordinary"},
	})
	if code != http.StatusOK {
		h.t.Fatalf("PreToolUse status %d: %v", code, out)
	}
	action, _ := out["action"].(string)
	var findings []string
	if list, ok := out["findings"].([]interface{}); ok {
		for _, item := range list {
			if text, ok := item.(string); ok {
				findings = append(findings, text)
			}
		}
	}
	return action, findings
}

// GAP-0806: a slow SessionStart (here a registration repair that waits) must
// not let the session's first tool call run before its verdict.
func TestCodexFirstToolCallWaitsForSlowSessionStart(t *testing.T) {
	previous := sessionStartGateMaxWait
	t.Cleanup(func() { sessionStartGateMaxWait = previous })
	h := newSessionStartGateHarness(t)

	startDone := make(chan int, 1)
	sessionStartGateMaxWait = 150 * time.Millisecond
	go func() { code, _ := h.post("SessionStart", "slow-blocked", nil); startDone <- code }()
	<-h.started
	if action, findings := h.toolCall("slow-blocked"); action != guardrailActionBlock || !slices.Contains(findings, "SESSION-START-PENDING") {
		t.Fatalf("first tool call during a slow start: action=%q findings=%v", action, findings)
	}
	h.repair <- errors.New("registration missing")
	if code := <-startDone; code != http.StatusServiceUnavailable {
		t.Fatalf("SessionStart status %d", code)
	}
	if action, findings := h.toolCall("slow-blocked"); action != guardrailActionBlock || !slices.Contains(findings, "SESSION-START-BLOCKED") {
		t.Fatalf("tool call after a blocked start: action=%q findings=%v", action, findings)
	}

	// A call waits for a start that is allowed in time, then runs.
	sessionStartGateMaxWait = 5 * time.Second
	go func() { code, _ := h.post("SessionStart", "slow-allowed", nil); startDone <- code }()
	<-h.started
	go func() {
		time.Sleep(100 * time.Millisecond)
		h.repair <- nil
	}()
	began := time.Now()
	if action, findings := h.toolCall("slow-allowed"); action == guardrailActionBlock {
		t.Fatalf("tool call after an allowed start: action=%q findings=%v", action, findings)
	}
	if waited := time.Since(began); waited < 50*time.Millisecond {
		t.Fatalf("the tool call did not wait for the start verdict (%s)", waited)
	}
	if code := <-startDone; code != http.StatusOK {
		t.Fatalf("SessionStart status %d", code)
	}
	// Another session is not held by this one.
	if action, findings := h.toolCall("other-session"); action == guardrailActionBlock {
		t.Fatalf("an unrelated session was held: %v", findings)
	}
	// Restarting the blocked session with an allowed start clears its block.
	go func() { code, _ := h.post("SessionStart", "slow-blocked", nil); startDone <- code }()
	<-h.started
	h.repair <- nil
	if code := <-startDone; code != http.StatusOK {
		t.Fatalf("restart SessionStart status %d", code)
	}
	if action, findings := h.toolCall("slow-blocked"); action == guardrailActionBlock {
		t.Fatalf("tool call after a new allowed start: action=%q findings=%v", action, findings)
	}
}

// The Claude Code first tool call that GAP-0806 saw run on Windows waits for
// the start in flight and is refused while it is pending or blocked.
func TestClaudeToolCallHeldBySessionStartInFlight(t *testing.T) {
	previous := sessionStartGateMaxWait
	t.Cleanup(func() { sessionStartGateMaxWait = previous })
	sessionStartGateMaxWait = 100 * time.Millisecond
	api := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
	api.scannerCfg.DataDir = t.TempDir()
	handler := api.handleUnifiedConnectorHook("claudecode")
	ctx := withAuthenticatedHookConnector(context.Background(), "claudecode")
	ticket := api.sessionStartGate.begin(sessionStartGateKey(ctx, "claudecode", "windows-slow-start"))
	call := func(event string, extra map[string]interface{}) (string, []string) {
		body := map[string]interface{}{"hook_event_name": event, "session_id": "windows-slow-start", "cwd": t.TempDir()}
		for key, value := range extra {
			body[key] = value
		}
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(string(raw)))
		req.Header.Set("X-DefenseClaw-Hook-Event", event)
		req.Header.Set("X-DefenseClaw-Hook-Contract", api.hookProfileForConnector("claudecode").ContractID)
		rec := httptest.NewRecorder()
		handler(rec, req.WithContext(ctx))
		var out map[string]interface{}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		action, _ := out["action"].(string)
		var findings []string
		if list, ok := out["findings"].([]interface{}); ok {
			for _, item := range list {
				if text, ok := item.(string); ok {
					findings = append(findings, text)
				}
			}
		}
		return action, findings
	}
	tool := map[string]interface{}{"tool_name": "Bash", "tool_input": map[string]interface{}{"command": "echo SAR4_CLAUDE_ALT_OK"}}
	for _, event := range []string{"UserPromptSubmit", "PreToolUse"} {
		extra := tool
		if event == "UserPromptSubmit" {
			extra = map[string]interface{}{"prompt": "run the echo"}
		}
		if action, findings := call(event, extra); action != guardrailActionBlock || !slices.Contains(findings, "SESSION-START-PENDING") {
			t.Fatalf("%s during the start: action=%q findings=%v", event, action, findings)
		}
	}
	ticket.finish(true, "the gateway did not answer in time")
	if action, findings := call("PreToolUse", tool); action != guardrailActionBlock || !slices.Contains(findings, "SESSION-START-BLOCKED") {
		t.Fatalf("PreToolUse after a blocked start: action=%q findings=%v", action, findings)
	}
	// Results and lifecycle events are not held: they run nothing.
	if action, findings := call("PostToolUse", tool); action == guardrailActionBlock {
		t.Fatalf("PostToolUse was held: %v", findings)
	}
}
