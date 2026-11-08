// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func TestGAP0647OpenClawInspectAuditCarriesInstallAgentIdentity(t *testing.T) {
	agentIdentityTestSetup(t)
	previous := identityFactsEnabled.Load()
	setIdentityFactsEnabled(true)
	t.Cleanup(func() { setIdentityFactsEnabled(previous) })
	self := gatewaySelfUser()
	if self.ID == "" {
		t.Fatal("gateway process owner has no identity")
	}
	base := withVerifiedSubject(t.Context(), VerifiedSubject{UserID: self.ID, UserName: self.Name})
	want := resolveHookAgentIdentity(base, agentHookRequest{ConnectorName: "openclaw"}).ID
	if want == "" {
		t.Fatal("OpenClaw install identity could not be derived")
	}
	for _, tc := range []struct {
		name, body, action string
	}{
		{"ordinary", `{"tool":"exec","args":{"command":"echo hello"}}`, string(audit.ActionInspectToolAllow)},
		{"protected", `{"tool":"exec","args":{"command":"echo note >> ~/.ssh/authorized_keys"}}`, string(audit.ActionInspectToolBlock)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := testAPIServerWithConfig(t, "action")
			api.scannerCfg.Guardrail.Connector = "openclaw"
			req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", strings.NewReader(tc.body)).WithContext(base)
			w := httptest.NewRecorder()
			api.handleInspectTool(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("inspect status=%d body=%s", w.Code, w.Body.String())
			}
			events, err := api.store.ListEvents(100)
			if err != nil {
				t.Fatal(err)
			}
			if tc.action == string(audit.ActionInspectToolBlock) {
				foundFinding := false
				for _, event := range events {
					if event.Action == "scan-finding" {
						foundFinding = true
						if event.AgentID != want {
							t.Fatalf("finding audit agent_id=%q, want %s", event.AgentID, want)
						}
					}
				}
				if !foundFinding {
					t.Fatal("protected inspect had no finding audit row")
				}
			}
			for _, event := range events {
				if event.Action != tc.action {
					continue
				}
				if got := event.Structured["defenseclaw.agent.identity.id"]; got != want {
					t.Fatalf("inspect audit identity=%v, want %s", got, want)
				}
				if event.AgentID != want {
					t.Fatalf("inspect audit agent_id=%q, want %s", event.AgentID, want)
				}
				return
			}
			t.Fatalf("inspect audit action %s was not recorded", tc.action)
		})
	}
}

func TestGAP0647OpenClawInspectKeepsExistingSessionIdentity(t *testing.T) {
	agentIdentityTestSetup(t)
	previous := identityFactsEnabled.Load()
	setIdentityFactsEnabled(true)
	t.Cleanup(func() { setIdentityFactsEnabled(previous) })
	self := gatewaySelfUser()
	base := withVerifiedSubject(t.Context(), VerifiedSubject{UserID: self.ID, UserName: self.Name})
	base = ContextWithAgentIdentity(base, AgentIdentity{
		AgentID: "openclaw-session-agent", AgentInstanceID: "ais-openclaw-session",
		UserID: self.ID, UserName: self.Name,
	})
	ctx := openClawInspectIdentity(base, "openclaw")
	identity := AgentIdentityFromContext(ctx)
	if identity.AgentID != "openclaw-session-agent" || identity.AgentInstanceID != "ais-openclaw-session" {
		t.Fatalf("session identity changed: %+v", identity)
	}
	if id, verified := agentIdentityFromContext(ctx); !verified || id == "" {
		t.Fatalf("verified install identity=%q, verified=%t", id, verified)
	}
}

func TestGAP0647UnverifiedInspectDoesNotClaimOpenClawIdentity(t *testing.T) {
	previous := identityFactsEnabled.Load()
	setIdentityFactsEnabled(true)
	t.Cleanup(func() { setIdentityFactsEnabled(previous) })
	ctx := openClawInspectIdentity(t.Context(), "openclaw")
	if id, _ := agentIdentityFromContext(ctx); id != "" {
		t.Fatalf("unverified inspect identity=%q", id)
	}
}

func TestGAP0647OpenClawInspectAssignsTheSessionInstanceFromTheVerifiedIdentity(t *testing.T) {
	agentIdentityTestSetup(t)
	previous := identityFactsEnabled.Load()
	setIdentityFactsEnabled(true)
	t.Cleanup(func() { setIdentityFactsEnabled(previous) })
	self := gatewaySelfUser()
	base := withVerifiedSubject(t.Context(), VerifiedSubject{UserID: self.ID, UserName: self.Name})
	instanceOf := func(session string) string {
		ctx := base
		if session != "" {
			ctx = ContextWithSessionID(ctx, session)
		}
		return AgentIdentityFromContext(openClawInspectIdentity(ctx, "openclaw")).AgentInstanceID
	}
	first := instanceOf("oc-session-1")
	if !strings.HasPrefix(first, "ais-") {
		t.Fatalf("session instance=%q, want an ais- id", first)
	}
	if again := instanceOf("oc-session-1"); again != first {
		t.Fatalf("same session instance=%q, want %q", again, first)
	}
	if other := instanceOf("oc-session-2"); other == first || !strings.HasPrefix(other, "ais-") {
		t.Fatalf("other session instance=%q, first=%q", other, first)
	}
	if none := instanceOf(""); none != "" {
		t.Fatalf("sessionless instance=%q, want none", none)
	}
}

func TestGAP0647OpenClawInspectRowsShareTheSessionInstance(t *testing.T) {
	agentIdentityTestSetup(t)
	previous := identityFactsEnabled.Load()
	setIdentityFactsEnabled(true)
	t.Cleanup(func() { setIdentityFactsEnabled(previous) })
	self := gatewaySelfUser()
	base := withVerifiedSubject(t.Context(), VerifiedSubject{UserID: self.ID, UserName: self.Name})
	base = ContextWithSessionID(base, "oc-session-rows")
	api := testAPIServerWithConfig(t, "action")
	api.scannerCfg.Guardrail.Connector = "openclaw"
	body := `{"tool":"exec","args":{"command":"echo note >> ~/.ssh/authorized_keys"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", strings.NewReader(body)).WithContext(base)
	w := httptest.NewRecorder()
	api.handleInspectTool(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("inspect status=%d body=%s", w.Code, w.Body.String())
	}
	events, err := api.store.ListEvents(100)
	if err != nil {
		t.Fatal(err)
	}
	instances := map[string]string{}
	for _, event := range events {
		if event.Action == "scan-finding" || event.Action == string(audit.ActionInspectToolBlock) {
			instances[event.Action] = event.AgentInstanceID
		}
	}
	if len(instances) != 2 {
		t.Fatalf("want a finding and an inspect block row, got %v", instances)
	}
	finding, inspect := instances["scan-finding"], instances[string(audit.ActionInspectToolBlock)]
	if !strings.HasPrefix(finding, "ais-") || finding != inspect {
		t.Fatalf("finding instance=%q, inspect instance=%q, want one shared ais- id", finding, inspect)
	}
}
