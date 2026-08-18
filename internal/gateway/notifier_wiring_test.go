// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/notifier"
	"github.com/defenseclaw/defenseclaw/internal/notify"
)

// recordingSender captures every notification that the dispatcher
// would deliver to the OS so test assertions can introspect title,
// subtitle, and body without touching osascript / notify-send.
//
// The dispatcher delivers via a goroutine, so the recorder waits on
// a counted WaitGroup-style channel rather than a slice append on
// the calling goroutine — “WaitFor(n)“ blocks up to a deadline so
// the wiring tests don't flake on a slow scheduler.
type recordingSender struct {
	mu     sync.Mutex
	sent   []notify.Notification
	signal chan struct{}
}

func newRecordingSender() *recordingSender {
	return &recordingSender{signal: make(chan struct{}, 64)}
}

func (r *recordingSender) Send(n notify.Notification) error {
	r.mu.Lock()
	r.sent = append(r.sent, n)
	r.mu.Unlock()
	select {
	case r.signal <- struct{}{}:
	default:
	}
	return nil
}

// WaitFor blocks until at least n notifications have been recorded
// or 1s has elapsed. Returns the captured notifications in arrival
// order; the deadline failure mode is a test fail rather than a
// silent empty slice so a wiring regression surfaces a useful name.
func (r *recordingSender) WaitFor(t *testing.T, n int) []notify.Notification {
	t.Helper()
	deadline := time.After(1 * time.Second)
	for {
		r.mu.Lock()
		got := len(r.sent)
		r.mu.Unlock()
		if got >= n {
			r.mu.Lock()
			out := append([]notify.Notification(nil), r.sent...)
			r.mu.Unlock()
			return out
		}
		select {
		case <-r.signal:
		case <-deadline:
			r.mu.Lock()
			out := append([]notify.Notification(nil), r.sent...)
			r.mu.Unlock()
			t.Fatalf("waited 1s for %d notifications, got %d: %+v",
				n, got, out)
			return nil
		}
	}
}

// fullyEnabledNotificationsConfig builds a NotificationsConfig that
// won't suppress anything, so a wiring test sees every emit. We
// deliberately do NOT call config.DefaultNotificationsConfig() here
// because that returns a platform-conditional Enabled — and on a
// linux CI runner that would silently disable the dispatcher.
func fullyEnabledNotificationsConfig() config.NotificationsConfig {
	return config.NotificationsConfig{
		Enabled:         true,
		BlockEnforced:   true,
		BlockWouldBlock: true,
		HITLApproval:    true,
		Sources: config.NotificationSourceFilter{
			Hook:        true,
			Guardrail:   true,
			AssetPolicy: true,
		},
		DedupWindow:  time.Second,
		MaxPerMinute: 1000,
	}
}

// newWiringDispatcher returns a dispatcher with a recording sender
// and a frozen clock so the dedup window in the test config never
// expires mid-test.
func newWiringDispatcher() (*notifier.Dispatcher, *recordingSender) {
	rec := newRecordingSender()
	d := notifier.NewWithSender(fullyEnabledNotificationsConfig(), rec.Send)
	frozen := time.Now()
	d.SetClock(func() time.Time { return frozen })
	return d, rec
}

// TestClaudeHookDispatch_BlockFiresOnBlock pins that the hook
// helper calls OnBlock and routes the right Source/Connector/Event
// fields onto the toast. A regression here would mean a successful
// block decision goes silent at the OS layer even when the operator
// has notifications enabled.
func TestClaudeHookDispatch_BlockFiresOnBlock(t *testing.T) {
	d, rec := newWiringDispatcher()
	api := &APIServer{}
	api.SetNotifier(d)

	req := claudeCodeHookRequest{
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
	}
	api.dispatchClaudeCodeHookNotification(
		req, "block", "block", "HIGH",
		"matched policy: deny-rm-rf", false,
		hookEvaluationContext{},
	)

	got := rec.WaitFor(t, 1)
	if len(got) != 1 {
		t.Fatalf("want 1 notification, got %d", len(got))
	}
	n := got[0]
	if !strings.Contains(strings.ToLower(n.Title), "block") {
		t.Errorf("title should mention 'block', got %q", n.Title)
	}
	// The dispatcher renders the target tool into the TITLE
	// ("DefenseClaw blocked Bash") rather than the body, which
	// holds the redacted reason. Pinning that here so a refactor
	// that flips title <-> body fields doesn't go unnoticed.
	if !strings.Contains(n.Title, "Bash") {
		t.Errorf("title should reference target tool 'Bash', got %q", n.Title)
	}
	if !strings.Contains(n.Subtitle, "claudecode") {
		t.Errorf("subtitle should carry connector 'claudecode', got %q", n.Subtitle)
	}
	if !strings.Contains(n.Subtitle, "PreToolUse") {
		t.Errorf("subtitle should carry hook event 'PreToolUse', got %q", n.Subtitle)
	}
}

// TestClaudeHookDispatch_WouldBlockFiresOnWouldBlock guards that
// observe-mode (rawAction=block, action!=block OR wouldBlock=true)
// routes through OnWouldBlock so the toast carries the "would have
// blocked" framing rather than implying the call was actually
// stopped.
func TestClaudeHookDispatch_WouldBlockFiresOnWouldBlock(t *testing.T) {
	d, rec := newWiringDispatcher()
	api := &APIServer{}
	api.SetNotifier(d)

	api.dispatchClaudeCodeHookNotification(
		claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "Bash"},
		"allow", "block", "MEDIUM", "observe-mode trial", true,
		hookEvaluationContext{},
	)

	got := rec.WaitFor(t, 1)
	if len(got) != 1 {
		t.Fatalf("want 1 notification, got %d", len(got))
	}
	if !strings.Contains(strings.ToLower(got[0].Title), "would") {
		t.Errorf("title should mention 'would', got %q", got[0].Title)
	}
}

// TestClaudeHookDispatch_ConfirmFiresOnApprovalPending guards the
// HITL/confirm route. A regression here would surface as missing
// approval-pending toasts even though the chat surface correctly
// asks for an answer.
func TestClaudeHookDispatch_ConfirmFiresOnApprovalPending(t *testing.T) {
	d, rec := newWiringDispatcher()
	api := &APIServer{}
	api.SetNotifier(d)

	api.dispatchClaudeCodeHookNotification(
		claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "Edit"},
		"confirm", "confirm", "LOW",
		"approval needed for write outside workspace", false,
		hookEvaluationContext{},
	)

	got := rec.WaitFor(t, 1)
	if len(got) != 1 {
		t.Fatalf("want 1 notification, got %d", len(got))
	}
	if !strings.Contains(strings.ToLower(got[0].Title), "approval") {
		t.Errorf("title should mention 'approval', got %q", got[0].Title)
	}
	// approvalNotification puts the subject ("Edit (PreToolUse)")
	// in the title; the body holds the redacted reason.
	if !strings.Contains(got[0].Title, "Edit") {
		t.Errorf("title should reference subject 'Edit', got %q", got[0].Title)
	}
}

// TestClaudeHookDispatch_RedactsReason pins the redaction contract:
// reasons that look like echoed user content (PII / secrets) must
// not land verbatim in the toast body. The dispatcher itself does
// not redact — the helper does — so a regression that drops the
// redaction.ForSinkReason call would silently leak content here.
func TestClaudeHookDispatch_RedactsReason(t *testing.T) {
	d, rec := newWiringDispatcher()
	api := &APIServer{}
	api.SetNotifier(d)

	rawSecret := "matched on user message: my-aws-key=AKIAIOSFODNN7EXAMPLE"
	api.dispatchClaudeCodeHookNotification(
		claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "Bash"},
		"block", "block", "HIGH", rawSecret, false,
		hookEvaluationContext{},
	)
	got := rec.WaitFor(t, 1)
	if strings.Contains(got[0].Body, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("toast body must not contain the raw AWS-key-shaped secret; "+
			"got %q", got[0].Body)
	}
}

// TestCodexHookDispatch_BlockFiresOnBlock mirrors the Claude Code
// happy-path test for the Codex helper. The two helpers carry the
// same routing contract — diverging on connector tag only — so a
// regression on either side surfaces here vs. the Claude test.
func TestCodexHookDispatch_BlockFiresOnBlock(t *testing.T) {
	d, rec := newWiringDispatcher()
	api := &APIServer{}
	api.SetNotifier(d)

	api.dispatchCodexHookNotification(
		codexHookRequest{HookEventName: "PreToolUse", ToolName: "shell"},
		"block", "block", "HIGH", "matched: blocked-shell", false,
		hookEvaluationContext{},
	)
	got := rec.WaitFor(t, 1)
	if !strings.Contains(got[0].Subtitle, "codex") {
		t.Errorf("subtitle should carry connector 'codex', got %q", got[0].Subtitle)
	}
}

// TestCodexHookDispatch_RedactsReason mirrors the redaction guard
// on the Codex helper — both sites must scrub before handing to the
// dispatcher so the privacy posture is symmetric across connectors.
func TestCodexHookDispatch_RedactsReason(t *testing.T) {
	d, rec := newWiringDispatcher()
	api := &APIServer{}
	api.SetNotifier(d)

	api.dispatchCodexHookNotification(
		codexHookRequest{HookEventName: "PreToolUse", ToolName: "shell"},
		"block", "block", "HIGH",
		"prompt contained AKIAIOSFODNN7EXAMPLE", false,
		hookEvaluationContext{},
	)
	got := rec.WaitFor(t, 1)
	if strings.Contains(got[0].Body, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("toast body must not contain the raw AWS-key-shaped secret; "+
			"got %q", got[0].Body)
	}
}

// TestAssetPolicyDispatch_BlockFiresOnBlock verifies the asset
// policy runtime helper routes a block decision to OnBlock with
// SourceAssetPolicy carried through. The asset policy surface is
// the only one of the four with default-HIGH severity (which is
// also asserted here as part of the fan-out contract).
func TestAssetPolicyDispatch_BlockFiresOnBlock(t *testing.T) {
	d, rec := newWiringDispatcher()
	api := &APIServer{}
	api.SetNotifier(d)

	decision := config.AssetPolicyDecision{
		Action:     "block",
		RawAction:  "block",
		Reason:     "skill 'spy' is on the deny list",
		TargetName: "spy",
	}
	api.dispatchAssetPolicyNotification(decision, "skill", "claudecode", "PreToolUse")

	got := rec.WaitFor(t, 1)
	if !strings.Contains(got[0].Subtitle, "HIGH") {
		t.Errorf("asset-policy toast should carry severity 'HIGH', got %q",
			got[0].Subtitle)
	}
	// Composite target ("skill:spy") is rendered into the title
	// because blockNotification wires Target into the title slot.
	if !strings.Contains(got[0].Title, "skill:spy") {
		t.Errorf("title should carry composite target 'skill:spy', got %q",
			got[0].Title)
	}
}

// TestAssetPolicyDispatch_RedactsReason guards the redaction
// scrub on the asset-policy helper — added at the same time as the
// hook helpers so the privacy posture is consistent across every
// dispatch site.
func TestAssetPolicyDispatch_RedactsReason(t *testing.T) {
	d, rec := newWiringDispatcher()
	api := &APIServer{}
	api.SetNotifier(d)

	decision := config.AssetPolicyDecision{
		Action:     "block",
		RawAction:  "block",
		Reason:     "user prompt mentioned AKIAIOSFODNN7EXAMPLE",
		TargetName: "demo",
	}
	api.dispatchAssetPolicyNotification(decision, "mcp", "codex", "PreToolUse")
	got := rec.WaitFor(t, 1)
	if strings.Contains(got[0].Body, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("asset-policy toast must not leak raw AWS-key-shaped string; "+
			"got %q", got[0].Body)
	}
}

// TestNotifierDisabled_NoEmit checks the master kill-switch: with
// notifications disabled in cfg, the dispatch helpers MUST NOT
// surface anything, even when the per-source toggle is on. This
// is the audit-trail-only mode an operator picks when they don't
// want a desktop toaster but still need every block recorded.
func TestNotifierDisabled_NoEmit(t *testing.T) {
	cfg := fullyEnabledNotificationsConfig()
	cfg.Enabled = false
	rec := newRecordingSender()
	d := notifier.NewWithSender(cfg, rec.Send)
	api := &APIServer{}
	api.SetNotifier(d)

	api.dispatchClaudeCodeHookNotification(
		claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "Bash"},
		"block", "block", "HIGH", "any reason", false,
		hookEvaluationContext{},
	)
	api.dispatchCodexHookNotification(
		codexHookRequest{HookEventName: "PreToolUse", ToolName: "shell"},
		"block", "block", "HIGH", "any reason", false,
		hookEvaluationContext{},
	)
	api.dispatchAssetPolicyNotification(
		config.AssetPolicyDecision{
			Action:     "block",
			RawAction:  "block",
			Reason:     "any",
			TargetName: "x",
		},
		"skill", "claudecode", "PreToolUse",
	)

	// Give any (errant) goroutine a tick to land before asserting
	// silence — we WANT zero, but a 0ms wait would race with the
	// production code path that defers the OS send to a goroutine.
	time.Sleep(50 * time.Millisecond)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.sent) != 0 {
		t.Fatalf("expected zero notifications when cfg.Enabled=false, got %d: %+v",
			len(rec.sent), rec.sent)
	}
}

// TestHILTDispatch_RequestFiresApprovalPending exercises the only
// remaining wiring site (HILTApprovalManager.Request) end-to-end:
// once the chat-side prompt is delivered, the manager must call
// notifier.OnApprovalPending so the operator gets a toast pointing
// them at chat. The test wires a recording dispatcher into the
// manager and a mock chat gateway that always succeeds the
// sessions.send call so Request() reaches the post-send branch.
//
// We use a short approval timeout so Request() returns promptly
// once the approval-pending toast has been emitted (we don't need
// to wait for the actual approve/deny round-trip — the toast
// surfaces immediately after sessions.send returns).
func TestHILTDispatch_RequestFiresApprovalPending(t *testing.T) {
	received := make(chan receivedRequest, 5)
	srv := startMockGW(t, rpcRecordingLoop(received))
	client := connectToMockGW(t, srv)

	m := NewHILTApprovalManager(client)
	m.TrackSession("session-A")

	d, rec := newWiringDispatcher()
	m.SetNotifier(d)

	done := make(chan string, 1)
	go func() {
		_, status, _ := m.Request(
			context.Background(),
			"",
			"exec",
			"HIGH",
			"approval needed: matched test policy",
			20*time.Millisecond,
		)
		done <- status
	}()

	rpc := drainRPC(t, received)
	if rpc.Method != "sessions.send" {
		t.Fatalf("expected sessions.send first, got %q", rpc.Method)
	}

	got := rec.WaitFor(t, 1)
	if !strings.Contains(strings.ToLower(got[0].Title), "approval") {
		t.Errorf("HILT toast title should mention 'approval', got %q", got[0].Title)
	}
	if !strings.Contains(got[0].Title, "exec") {
		t.Errorf("HILT toast title should reference subject 'exec', got %q", got[0].Title)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("approval request did not finish")
	}
}

// TestProxyDispatch_BlockEnqueuesGuardrailToast pins the guardrail
// surface: a verdict that lands at enqueueBlockNotification must
// reach the dispatcher with Source=Guardrail and the model name
// carried into the toast title. This is the surface every chat-
// completion block goes through, so a wiring regression here
// silences the most common toast in production.
func TestProxyDispatch_BlockEnqueuesGuardrailToast(t *testing.T) {
	d, rec := newWiringDispatcher()
	p := &GuardrailProxy{}
	p.SetNotifier(d)

	verdict := &ScanVerdict{
		Action:   "block",
		Reason:   "test verdict reason",
		Severity: "HIGH",
	}
	p.enqueueBlockNotification(verdict, "prompt", "claude-3.5-sonnet")

	got := rec.WaitFor(t, 1)
	if !strings.Contains(got[0].Title, "claude-3.5-sonnet") {
		t.Errorf("title should reference model name, got %q", got[0].Title)
	}
	if !strings.Contains(got[0].Subtitle, "guardrail") {
		t.Errorf("subtitle should carry source 'guardrail', got %q", got[0].Subtitle)
	}
}

// TestProxyDispatch_WouldBlockEnqueuesObserveToast guards the
// observe-mode path — the operator who flips guardrail to observe
// to measure false positives still wants to see toasts. The body
// must say "would block" not "blocked" so the operator doesn't
// chase a nonexistent enforcement incident.
func TestProxyDispatch_WouldBlockEnqueuesObserveToast(t *testing.T) {
	d, rec := newWiringDispatcher()
	p := &GuardrailProxy{}
	p.SetNotifier(d)

	verdict := &ScanVerdict{
		Action:   "block",
		Reason:   "would-block sample",
		Severity: "MEDIUM",
	}
	p.enqueueWouldBlockNotification(verdict, "completion", "gpt-4o")

	got := rec.WaitFor(t, 1)
	if !strings.Contains(strings.ToLower(got[0].Title), "would") {
		t.Errorf("would-block toast title should mention 'would', got %q",
			got[0].Title)
	}
}

// TestProxyDispatch_RedactsReason locks down the privacy posture
// for the guardrail surface specifically — the regex_match path
// can mint reasons from echoed user content, which is exactly the
// shape that would leak secrets onto the lock screen.
func TestProxyDispatch_RedactsReason(t *testing.T) {
	d, rec := newWiringDispatcher()
	p := &GuardrailProxy{}
	p.SetNotifier(d)

	verdict := &ScanVerdict{
		Action:   "block",
		Reason:   "regex hit on AKIAIOSFODNN7EXAMPLE in user input",
		Severity: "HIGH",
	}
	p.enqueueBlockNotification(verdict, "prompt", "claude-3.5-sonnet")
	got := rec.WaitFor(t, 1)
	if strings.Contains(got[0].Body, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("guardrail toast must not leak raw AWS-key-shaped string; "+
			"got %q", got[0].Body)
	}
}

// TestNotifierSourceFilter_AssetPolicyOff verifies the per-source
// toggle gates a category cleanly: with asset_policy off but hook
// on, the hook helper still emits but the asset policy helper does
// not. This is the noise-floor knob an operator turns down when
// asset policy spam is the issue.
func TestNotifierSourceFilter_AssetPolicyOff(t *testing.T) {
	cfg := fullyEnabledNotificationsConfig()
	cfg.Sources.AssetPolicy = false
	rec := newRecordingSender()
	d := notifier.NewWithSender(cfg, rec.Send)
	api := &APIServer{}
	api.SetNotifier(d)

	api.dispatchAssetPolicyNotification(
		config.AssetPolicyDecision{
			Action:     "block",
			RawAction:  "block",
			Reason:     "blocked",
			TargetName: "demo",
		},
		"skill", "claudecode", "PreToolUse",
	)
	api.dispatchClaudeCodeHookNotification(
		claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "Bash"},
		"block", "block", "HIGH", "hook block", false,
		hookEvaluationContext{},
	)

	got := rec.WaitFor(t, 1)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 notification (hook only), got %d", len(got))
	}
	if !strings.Contains(got[0].Subtitle, "claudecode") {
		t.Errorf("the only notification should be the hook (claudecode), got %q",
			got[0].Subtitle)
	}
}
