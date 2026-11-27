// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// GAP-1149: the envelope's event is the actor's own text. A program in the
// actor posted an envelope whose event was an exposed actor_secrets value,
// with the value in the payload too: the payload was masked, but the event
// reached the substrate.exposed_secret_masked row (summary and hook_event),
// the decision row, the hook audit envelope and the handler's event header
// in clear. Now an event name that is not a short identifier, or holds an
// exposed value, is refused before any row, log or header carries it.
func TestGAP1149EventNameNeverCarriesAnExposedValue(t *testing.T) {
	const value = "9f3c1a7e5b2d4c6a8e0f1b3d5a7c9e2f"
	reg := registry.Registration{Atespace: "eng-web", Name: "alice-1", UID: subUID1, Connector: "claudecode", Profile: "eng",
		Person: registry.Person{Kind: "oidc", Issuer: "https://idp.example", Subject: "s-1", Principal: "alice@example.com"}}
	for _, tc := range []struct {
		name, event, header string
	}{
		{"event is the value", value, ""},
		{"event holds the value", "PreToolUse" + value, ""},
		{"event holds it base64", "x" + "OWYzYzFhN2U1YjJkNGM2YThlMGYxYjNkNWE3YzllMmY", ""},
		{"header is the value", "", value},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSubstrateFixture(t)
			st := f.api.substrateState()
			st.cfg.LLM = &substrateLLM{cfg: SubstrateLLMConfig{ExposedValues: func(string) map[string]string {
				return map[string]string{"sv17-exposed": value}
			}}}
			var rows []string
			st.audit = func(_ context.Context, _, summary string, details map[string]any) {
				b, _ := json.Marshal(details)
				rows = append(rows, summary+" "+string(b))
			}
			var log strings.Builder
			st.logOut = &log
			reached := false
			h := substrateEnvelopeMiddleware(st, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				for _, name := range substrateEventHeaders {
					if strings.Contains(r.Header.Get(name), value) {
						t.Errorf("the handler's %s header carries the value", name)
					}
				}
				if env, ok := substrateEnvelopeFrom(r.Context()); ok && strings.Contains(env.Event, value) {
					t.Error("the envelope the handler reads carries the value as its event")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"action":"allow"}`))
			}))
			p, _ := json.Marshal(map[string]any{"hook_event_name": "PostToolUse", "tool_name": "Bash",
				"tool_response": map[string]any{"stdout": "the token is " + value}})
			body, _ := json.Marshal(map[string]any{"v": substrateEnvelopeVersion, "connector": "claudecode", "event": tc.event,
				"mode": "interactive", "kit_version": "0.1.0", "payload": json.RawMessage(p)})
			ctx := context.WithValue(context.Background(), substrateRegistrationKey{}, reg)
			ctx = withSubstrateRoute(ctx, substrateActorRoute{class: sandboxauth.RouteHook, connector: "claudecode"})
			req := httptest.NewRequest(http.MethodPost, substrateHookPrefix+"claudecode", strings.NewReader(string(body))).WithContext(ctx)
			if tc.header != "" {
				req.Header.Set("X-DefenseClaw-Hook-Event", tc.header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			for _, row := range rows {
				if strings.Contains(row, value) || strings.Contains(row, tc.event[min(len(tc.event), 1):]) && tc.event != "" {
					t.Errorf("an audit row carries the event text: %s", row)
				}
			}
			if strings.Contains(log.String(), value) {
				t.Errorf("the gateway log carries the value: %s", log.String())
			}
			if rec.Code != http.StatusBadRequest || reasonOf(t, rec) != "envelope_event_invalid" || reached {
				t.Fatalf("status %d reason %q (handler reached %v), want 400 envelope_event_invalid", rec.Code, reasonOf(t, rec), reached)
			}
		})
	}
}

// GAP-1149: no event a connector declares is refused (no false block above
// rel), and the shape rule refuses what no connector sends.
func TestGAP1149EveryDeclaredEventNameIsAccepted(t *testing.T) {
	exposed := map[string]string{"api-key": "AbCdEf0123456789GhIjKlMn"}
	n := 0
	for _, name := range []string{"claudecode", "codex", "opencode", "copilot", "hermes", "kiro", "antigravity", "cursor", "amp", "devin", "gemini", "windsurf", "openclaw"} {
		for _, c := range connector.KnownHookContracts(name) {
			for _, ev := range c.Events {
				n++
				if !substrateEventNameOK(ev, exposed) {
					t.Errorf("%s (%s) declares %q, refused", name, c.ContractID, ev)
				}
			}
		}
	}
	for _, ev := range connector.CorrelationLifecycleEventNames(connector.CorrelationLifecycleSessionStart, connector.CorrelationLifecycleSessionEnd,
		connector.CorrelationLifecycleTurnStart, connector.CorrelationLifecycleTurnEnd, connector.CorrelationLifecycleToolStart,
		connector.CorrelationLifecycleToolEnd, connector.CorrelationLifecycleSubagentStart, connector.CorrelationLifecycleSubagentEnd) {
		n++
		if !substrateEventNameOK(ev, exposed) {
			t.Errorf("map event %q refused", ev)
		}
	}
	if n < 50 {
		t.Fatalf("only %d declared events checked", n)
	}
	for _, bad := range []string{"PreToolUse\n", "Pre ToolUse", "1PreToolUse", "a\"b", strings.Repeat("a", substrateEventMaxLen+1), "x/y", "AbCdEf0123456789GhIjKlMn"} {
		if substrateEventNameOK(bad, exposed) {
			t.Errorf("%q accepted", bad)
		}
	}
	if !substrateEventNameOK("", exposed) {
		t.Error("an envelope without an event (the payload names it) was refused")
	}
}
