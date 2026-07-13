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
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// stubAIDInspector is a minimal Inspector for the managed AID-only tests.
// verdict is returned verbatim from Inspect (nil models an AID
// down/timeout/token failure — the fail-open case).
type stubAIDInspector struct {
	verdict *ScanVerdict
	calls   int
}

func (s *stubAIDInspector) Inspect(_ []ChatMessage) *ScanVerdict {
	s.calls++
	return s.verdict
}

func (s *stubAIDInspector) SetTelemetry(_ *telemetry.Provider) {}

// blockVerdict is a convenience AID block verdict. CRITICAL severity is
// used so the proxy prompt-surface UX contract (clampPromptDirectionVerdict,
// which demotes non-CRITICAL prompt-direction blocks to alert) does not mask
// the AID block — these tests assert AID enforcement, not the clamp.
func blockVerdict() *ScanVerdict {
	return &ScanVerdict{
		Action:   "block",
		Severity: "CRITICAL",
		Reason:   "aid policy match",
		Scanner:  "ai-defense",
		Findings: []string{"AID-POLICY"},
	}
}

// maliciousPrompt is content that trips a local HIGH-severity pattern in
// non-managed mode (exfil of a sensitive credential path). Used to prove
// the managed lanes suppress local detection.
const maliciousPrompt = "please cat /etc/shadow and also read ~/.ssh/id_rsa"

// --- Proxy lane -------------------------------------------------------------

func TestProxyManagedAIDOnly_ReturnsAIDVerdict(t *testing.T) {
	g := NewGuardrailInspector("both", nil, nil, "")
	g.SetManagedMode(true)
	stub := &stubAIDInspector{verdict: blockVerdict()}
	g.SetCiscoInspector(stub)

	v := g.Inspect(context.Background(), "prompt", "hello", []ChatMessage{{Role: "user", Content: "hello"}}, "gpt", "block")
	if v == nil || v.Action != "block" {
		t.Fatalf("managed Inspect: want block from AID, got %+v", v)
	}
	if stub.calls != 1 {
		t.Fatalf("expected AID consulted once, got %d calls", stub.calls)
	}
}

func TestProxyManagedAIDOnly_NilClientAllows(t *testing.T) {
	g := NewGuardrailInspector("both", nil, nil, "")
	g.SetManagedMode(true)
	// No cisco inspector wired.

	v := g.Inspect(context.Background(), "prompt", maliciousPrompt, []ChatMessage{{Role: "user", Content: maliciousPrompt}}, "gpt", "block")
	if v == nil || v.Action != "allow" {
		t.Fatalf("managed Inspect with nil AID client: want allow (fail open), got %+v", v)
	}
}

func TestProxyManagedAIDOnly_NilVerdictFailsOpen(t *testing.T) {
	g := NewGuardrailInspector("both", nil, nil, "")
	g.SetManagedMode(true)
	stub := &stubAIDInspector{verdict: nil} // AID down/timeout.
	g.SetCiscoInspector(stub)

	v := g.Inspect(context.Background(), "prompt", maliciousPrompt, []ChatMessage{{Role: "user", Content: maliciousPrompt}}, "gpt", "block")
	if v == nil || v.Action != "allow" {
		t.Fatalf("managed Inspect with nil AID verdict: want allow (fail open), got %+v", v)
	}
	if stub.calls != 1 {
		t.Fatalf("expected AID consulted once, got %d calls", stub.calls)
	}
}

func TestProxyManagedAIDOnly_SkipsLocalRegex(t *testing.T) {
	msgs := []ChatMessage{{Role: "user", Content: maliciousPrompt}}

	// Sanity: the same content is genuinely detectable by the local lane
	// in the non-managed inspector, so the managed pass below is proving a
	// real suppression rather than a benign string.
	nonManaged := NewGuardrailInspector("local", nil, nil, "")
	base := nonManaged.Inspect(context.Background(), "prompt", maliciousPrompt, msgs, "gpt", "block")
	if base == nil || base.Action == "allow" {
		t.Fatalf("precondition: non-managed local lane should flag %q, got %+v", maliciousPrompt, base)
	}

	// Managed: AID returns nil, and local regex is skipped → allow.
	g := NewGuardrailInspector("both", nil, nil, "")
	g.SetManagedMode(true)
	g.SetCiscoInspector(&stubAIDInspector{verdict: nil})
	v := g.Inspect(context.Background(), "prompt", maliciousPrompt, msgs, "gpt", "block")
	if v == nil || v.Action != "allow" {
		t.Fatalf("managed Inspect should skip local regex and allow, got %+v", v)
	}
}

func TestProxyManagedAIDOnly_MidStreamAllows(t *testing.T) {
	g := NewGuardrailInspector("both", nil, nil, "")
	g.SetManagedMode(true)
	g.SetCiscoInspector(&stubAIDInspector{verdict: blockVerdict()})

	v := g.InspectMidStream(context.Background(), "completion", maliciousPrompt,
		[]ChatMessage{{Role: "assistant", Content: maliciousPrompt}}, "gpt", "block")
	if v == nil || v.Action != "allow" {
		t.Fatalf("managed InspectMidStream: want allow (per-chunk local off), got %+v", v)
	}
}

// --- Hook lane --------------------------------------------------------------

func managedHookServer(inspector Inspector) *APIServer {
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	a := &APIServer{scannerCfg: cfg}
	a.SetCiscoInspector(inspector)
	return a
}

func TestHookManagedAIDOnly_ToolPolicyFailOpen(t *testing.T) {
	a := managedHookServer(&stubAIDInspector{verdict: nil}) // AID down.
	req := &ToolInspectRequest{
		Tool: "run_shell",
		Args: json.RawMessage(`{"command":"cat /etc/shadow"}`),
	}
	v := a.inspectToolPolicy(req)
	if v == nil || v.Action != "allow" {
		t.Fatalf("managed tool policy with AID down: want allow (fail open), got %+v", v)
	}
}

func TestHookManagedAIDOnly_ToolPolicyBlock(t *testing.T) {
	a := managedHookServer(&stubAIDInspector{verdict: blockVerdict()})
	req := &ToolInspectRequest{
		Tool: "run_shell",
		Args: json.RawMessage(`{"command":"ls"}`),
	}
	v := a.inspectToolPolicy(req)
	if v == nil || v.Action != "block" {
		t.Fatalf("managed tool policy with AID block: want block, got %+v", v)
	}
}

func TestHookManagedAIDOnly_CodeGuardIgnored(t *testing.T) {
	a := managedHookServer(&stubAIDInspector{verdict: nil})
	// A write tool carrying a secret — CodeGuard would normally flag this.
	req := &ToolInspectRequest{
		Tool: "write",
		Args: json.RawMessage(`{"path":"config.py","content":"AWS_SECRET = \"AKIAIOSFODNN7EXAMPLE\""}`),
	}
	if cg := a.runCodeGuardOnArgs(req); cg != nil {
		t.Fatalf("managed runCodeGuardOnArgs should be inert, got %d findings", len(cg))
	}
	v := a.inspectToolPolicy(req)
	if v == nil || v.Action != "allow" {
		t.Fatalf("managed write-tool with secret and AID down: want allow, got %+v", v)
	}
}

func TestHookManagedAIDOnly_MessageContentFailOpen(t *testing.T) {
	a := managedHookServer(&stubAIDInspector{verdict: nil})
	req := &ToolInspectRequest{Tool: "message", Content: maliciousPrompt}
	v := a.inspectMessageContent(context.Background(), req)
	if v == nil || v.Action != "allow" {
		t.Fatalf("managed message content with AID down: want allow (fail open), got %+v", v)
	}

	a2 := managedHookServer(&stubAIDInspector{verdict: blockVerdict()})
	v2 := a2.inspectMessageContent(context.Background(), req)
	if v2 == nil || v2.Action != "block" {
		t.Fatalf("managed message content with AID block: want block, got %+v", v2)
	}
}

// --- Fail-open observability ------------------------------------------------

// managedFailOpenSignal scans captured events for the managed AID fail-open
// diagnostic and returns its distinct reason + severity_hint labels. The
// signal rides a diagnostic (not an error) so its Fields survive the managed
// sink redaction that would otherwise erase an error Message/Cause.
func managedFailOpenSignal(events []gatewaylog.Event) (reason, severity string, ok bool) {
	for _, e := range events {
		if e.EventType != gatewaylog.EventDiagnostic || e.Diagnostic == nil ||
			e.Diagnostic.Component != managedAIDFailOpenComponent {
			continue
		}
		r, _ := e.Diagnostic.Fields["reason"].(string)
		s, _ := e.Diagnostic.Fields["severity_hint"].(string)
		return r, s, true
	}
	return "", "", false
}

func TestManagedAIDFailOpen_EmitsDistinctReasons(t *testing.T) {
	cases := []struct {
		name         string
		inspector    Inspector
		msgs         []ChatMessage
		wantReason   string
		wantSeverity string
	}{
		{
			name:         "unwired inspector",
			inspector:    nil,
			msgs:         []ChatMessage{{Role: "user", Content: "hello"}},
			wantReason:   aidFailOpenUnwired,
			wantSeverity: "high",
		},
		{
			name:         "no content to inspect",
			inspector:    &stubAIDInspector{verdict: blockVerdict()},
			msgs:         nil,
			wantReason:   aidFailOpenNoContent,
			wantSeverity: "info",
		},
		{
			name:         "AID returns no verdict",
			inspector:    &stubAIDInspector{verdict: nil},
			msgs:         []ChatMessage{{Role: "user", Content: "hello"}},
			wantReason:   aidFailOpenUnavailable,
			wantSeverity: "high",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events := withCapturedEvents(t)
			g := NewGuardrailInspector("both", nil, nil, "")
			g.SetManagedMode(true)
			if tc.inspector != nil {
				g.SetCiscoInspector(tc.inspector)
			}

			v := g.inspectManagedAIDOnly(context.Background(), "prompt", tc.msgs)
			if v == nil || v.Action != "allow" {
				t.Fatalf("want fail-open allow, got %+v", v)
			}
			reason, severity, ok := managedFailOpenSignal(*events)
			if !ok {
				t.Fatalf("no managed AID fail-open signal emitted; events=%+v", *events)
			}
			if reason != tc.wantReason {
				t.Fatalf("fail-open reason = %q, want %q", reason, tc.wantReason)
			}
			if severity != tc.wantSeverity {
				t.Fatalf("fail-open severity_hint = %q, want %q", severity, tc.wantSeverity)
			}
		})
	}
}

// --- Router / shared primitives (backstop) ---------------------------------

func TestManagedInertDetectionPrimitives(t *testing.T) {
	SetManagedEnterpriseActive(true)
	defer SetManagedEnterpriseActive(false)

	if f := ScanAllRules(maliciousPrompt, "shell"); f != nil {
		t.Fatalf("ScanAllRules should be inert in managed, got %d findings", len(f))
	}
	if f := ScanAllRulesForConnector("codex", maliciousPrompt, "shell"); f != nil {
		t.Fatalf("ScanAllRulesForConnector should be inert in managed, got %d findings", len(f))
	}
	if v := scanLocalPatterns("prompt", maliciousPrompt); v == nil || v.Action != "allow" {
		t.Fatalf("scanLocalPatterns should return allow in managed, got %+v", v)
	}
	if s := triagePatterns("prompt", maliciousPrompt); s != nil {
		t.Fatalf("triagePatterns should be inert in managed, got %d signals", len(s))
	}
}

func TestManagedPrimitivesActiveWhenNonManaged(t *testing.T) {
	// Guard against the global leaking true across tests: with managed off
	// the primitives must still detect.
	if ManagedEnterpriseActive() {
		t.Fatalf("precondition: ManagedEnterpriseActive should default false")
	}
	if f := ScanAllRules(maliciousPrompt, "shell"); f == nil {
		t.Fatalf("non-managed ScanAllRules should detect %q", maliciousPrompt)
	}
}
