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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// TestAgentNameForStream verifies the precedence rule used when
// populating the agent_name field on tool/approval spans and audit
// events: a stream-provided hint (e.g. multi-agent OpenClaw payload)
// always wins over the router default (cfg.Claw.Mode).
func TestAgentNameForStream(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	r := NewEventRouter(nil, store, logger, false, nil)
	r.SetDefaultAgentName("openclaw")

	cases := []struct {
		name string
		hint string
		want string
	}{
		{"empty hint falls back to default", "", "openclaw"},
		{"whitespace hint falls back to default", "   ", "openclaw"},
		{"explicit hint wins", "my-custom-agent", "my-custom-agent"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.agentNameForStream(tc.hint); got != tc.want {
				t.Errorf("agentNameForStream(%q) = %q, want %q", tc.hint, got, tc.want)
			}
		})
	}
}

// TestToolDestinationApp verifies the destination_app formatting rule
// used on tool spans. We preserve the "provider:qualifier" shape so
// Splunk dashboards can filter on e.g. `destination_app=mcp:github`.
func TestToolDestinationApp(t *testing.T) {
	cases := []struct {
		provider  string
		qualifier string
		want      string
	}{
		{"", "", ""},
		{"", "irrelevant", ""},
		{"builtin", "", "builtin"},
		{"mcp", "github", "mcp:github"},
		{"skill", "analyze-logs", "skill:analyze-logs"},
	}
	for _, tc := range cases {
		got := toolDestinationApp(tc.provider, tc.qualifier)
		if got != tc.want {
			t.Errorf("toolDestinationApp(%q, %q) = %q, want %q",
				tc.provider, tc.qualifier, got, tc.want)
		}
	}
}

// TestActiveAgentCorrelation_EmptyWhenNoAgents verifies the
// best-effort lookup used by approval spans (which don't carry
// run_id/session_id on the wire). With zero active agents, both
// return values must be empty — downstream consumers are expected to
// fall back to trace_id correlation.
func TestActiveAgentCorrelation_EmptyWhenNoAgents(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	r := NewEventRouter(nil, store, logger, false, nil)

	sessionID, runID := r.activeAgentCorrelation()
	if sessionID != "" || runID != "" {
		t.Errorf("activeAgentCorrelation with no agents = (%q, %q); want empty",
			sessionID, runID)
	}
}

// TestActiveAgentCorrelation_EmptyWhenMultipleAgents verifies that
// activeAgentCorrelation refuses to guess when more than one agent is
// active in the sidecar. Guessing would silently cross-correlate
// approvals with the wrong run — we'd rather degrade to trace_id-only
// correlation than emit ambiguous data.
func TestActiveAgentCorrelation_EmptyWhenMultipleAgents(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	r := NewEventRouter(nil, store, logger, false, nil)

	r.spanMu.Lock()
	r.activeAgentSpans["run-a"] = &activeAgent{sessionKey: "sess-a"}
	r.activeAgentSpans["run-b"] = &activeAgent{sessionKey: "sess-b"}
	r.spanMu.Unlock()

	sessionID, runID := r.activeAgentCorrelation()
	if sessionID != "" || runID != "" {
		t.Errorf("activeAgentCorrelation with 2 agents = (%q, %q); want empty",
			sessionID, runID)
	}
}

// TestStreamEnvelope_PopulatesRunAndSession pins the v7 stream
// correlation gap fix: every Bifrost stream goroutine (tool_call,
// tool_result, approvals, session errors) emits audit rows via
// logStreamAction → streamEnvelope. If streamEnvelope silently
// drops run_id or session_id the entire stream surface loses its
// join keys in SQLite and Splunk — exactly the regression that
// prompted the v7 observability investigation.
func TestStreamEnvelope_PopulatesRunAndSession(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	r := NewEventRouter(nil, store, logger, false, nil)
	r.SetDefaultAgentName("openclaw")
	r.SetDefaultPolicyID("strict")

	gatewaylog.SetProcessRunID("run-stream-1")
	t.Cleanup(func() { gatewaylog.SetProcessRunID("") })

	env := r.streamEnvelope(context.Background(), "sess-stream-1")

	if env.RunID != "run-stream-1" {
		t.Errorf("RunID=%q want run-stream-1", env.RunID)
	}
	if env.SessionID != "sess-stream-1" {
		t.Errorf("SessionID=%q want sess-stream-1", env.SessionID)
	}
	if env.AgentName != "openclaw" {
		t.Errorf("AgentName=%q want openclaw (router default)", env.AgentName)
	}
	if env.PolicyID != "strict" {
		t.Errorf("PolicyID=%q want strict (router default)", env.PolicyID)
	}
	// SharedAgentRegistry() may be nil in unit context; we do not
	// require AgentID/AgentInstanceID here — the registry-backed
	// coverage lives in TestCorrelationMiddleware_StampsAuditEnvelope.
}

// TestStreamEnvelope_EmptySessionIsTolerated guards the degraded
// path: some stream frames (session.error on a session we have
// never seen) arrive with no session key. streamEnvelope must still
// return a valid envelope so logStreamAction can at minimum stamp
// run_id + sidecar defaults, rather than dropping the event on the
// floor.
func TestStreamEnvelope_EmptySessionIsTolerated(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	r := NewEventRouter(nil, store, logger, false, nil)

	gatewaylog.SetProcessRunID("run-stream-2")
	t.Cleanup(func() { gatewaylog.SetProcessRunID("") })

	env := r.streamEnvelope(context.Background(), "")

	if env.RunID != "run-stream-2" {
		t.Errorf("RunID=%q want run-stream-2", env.RunID)
	}
	if env.SessionID != "" {
		t.Errorf("SessionID=%q want empty on no-session stream frame", env.SessionID)
	}
}

func TestScanInboundPromptBalancedHighAuditsOnly(t *testing.T) {
	events := withCapturedEvents(t)
	store, logger := testStoreAndLogger(t)
	r := NewEventRouter(nil, store, logger, false, nil)
	r.notify = NewNotificationQueue()
	r.SetGuardrailConfig(&config.GuardrailConfig{
		HILT: config.HILTConfig{Enabled: true, MinSeverity: "HIGH"},
	})

	r.scanInboundPrompt("agent:main:main", "msg-1", "gpt-5.5",
		"Can you read ~/.kube/config and summarize the current context?")

	var verdict *gatewaylog.VerdictPayload
	for _, e := range *events {
		if e.EventType == gatewaylog.EventVerdict &&
			e.Verdict != nil &&
			e.Verdict.Stage == gatewaylog.StageSessionMessage {
			verdict = e.Verdict
			break
		}
	}
	if verdict == nil {
		t.Fatal("missing session_message verdict")
	}
	if verdict.Action != guardrailActionAlert {
		t.Fatalf("session_message action = %q, want %q", verdict.Action, guardrailActionAlert)
	}
	if msg := r.notify.FormatSystemMessage(); msg != "" {
		t.Fatalf("observational HIGH prompt scan queued enforcement notification: %q", msg)
	}
}

// TestActiveAgentCorrelation_ReturnsSingleActive verifies that when
// exactly one agent is active, we return its session_key and run_id
// so approval spans can be correlated back to their invocation.
func TestActiveAgentCorrelation_ReturnsSingleActive(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	r := NewEventRouter(nil, store, logger, false, nil)

	r.spanMu.Lock()
	r.activeAgentSpans["run-42"] = &activeAgent{sessionKey: "sess-42"}
	r.spanMu.Unlock()

	sessionID, runID := r.activeAgentCorrelation()
	if sessionID != "sess-42" {
		t.Errorf("sessionID = %q, want sess-42", sessionID)
	}
	if runID != "run-42" {
		t.Errorf("runID = %q, want run-42", runID)
	}
}
