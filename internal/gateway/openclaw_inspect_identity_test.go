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
