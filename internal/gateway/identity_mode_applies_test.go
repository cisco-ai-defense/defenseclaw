// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Review of r104 Q-identity (continuation 5, loop round 1): an unproven
// identity fact must be refused only where the mode that applies to the
// request blocks under a strict candidate. Two surfaces read another mode
// than the one the refusal read:
//   - ACP applies its own mode (acp.mode, acp.profiles.<p>.mode), but an
//     identity refusal blocked in every ACP mode, so an observe ACP pair
//     was blocked by a candidate in strict action mode, which its own
//     verdicts never are. In observe mode the refusal is now reported as
//     would-block, as a method denial is; action mode still refuses.
//   - /api/v1/inspect/tool applies the mode of the gateway's own connector
//     to a credential not scoped to one, but the refusal read the global
//     settings, so a candidate's global strict action refused a connector
//     it sets to observe, and a strict per-connector action did not
//     refuse. The refusal now reads the connector whose mode applies.
func TestUnprovenRefusalFollowsTheModeThatApplies(t *testing.T) {
	resetConnectorRuleCategories(t)
	withLocalPatternsRestored(t)
	priorManaged := ManagedEnterpriseActive()
	setManagedEnterpriseRedactionPosture(false)
	t.Cleanup(func() { setManagedEnterpriseRedactionPosture(priorManaged) })
	previous := liveGuardrailProfiles.Load()
	t.Cleanup(func() { liveGuardrailProfiles.Store(previous) })
	stubProfileSources(t)
	p := identityTestPlatforms[0]
	unknown := identityTestSubject(p, p.providers[1], stateGroupsUnknown, false)
	const fact = "group membership is unconfirmed"

	// newAPI is a gateway whose default, watch, observes, and whose group
	// assignment, which the unknown group fact may give, is strict: the
	// strict rule pack in global mode global, with connector modes
	// connectors. Its own connector is OpenClaw, and its ACP pair is in
	// acpMode.
	newAPI := func(t *testing.T, global string, connectors map[string]string, acpMode string) *APIServer {
		t.Helper()
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "observe"
		cfg.Guardrail.Connector = "openclaw"
		strict := strictTier(t, cfg, config.GuardrailProfile{}, "strict")
		strict.Mode = global
		for name, mode := range connectors {
			if strict.Connectors == nil {
				strict.Connectors = map[string]config.PerConnectorGuardrailConfig{}
			}
			strict.Connectors[name] = config.PerConnectorGuardrailConfig{Mode: mode}
		}
		cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"watch": {Mode: "observe"}, "strict": strict}
		cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: "strict", Match: config.ProfileMatch{Groups: []string{p.group}}}}
		cfg.Guardrail.DefaultProfile = "watch"
		cfg.ACP = config.ACPConfig{
			Enabled: true, Mode: acpMode, DefaultProfile: "default",
			Clients: map[string]config.ACPBinding{"zed": {Enabled: true, Profile: "default"}},
			Agents:  map[string]config.ACPBinding{"kiro": {Enabled: true, Profile: "default"}},
			Profiles: map[string]config.ACPProfile{"default": {
				Mode: acpMode, AllowedClients: []string{"zed"}, AllowedAgents: []string{"kiro"},
			}},
		}
		return NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil, cfg)
	}

	t.Run("ACP", func(t *testing.T) {
		for _, tc := range []struct {
			name, acpMode string
			connectors    map[string]string
			// block: the verdict blocks; wouldBlock: an observe verdict
			// reports the refusal; refused: the reason names the fact.
			block, wouldBlock, refused bool
		}{
			{name: "observe ACP pair, strict action candidate", acpMode: "observe",
				wouldBlock: true, refused: true},
			{name: "action ACP pair, strict action candidate", acpMode: "action",
				block: true, refused: true},
			{name: "action ACP pair, the candidate observes the ACP agent's connector", acpMode: "action",
				connectors: map[string]string{"kiro": "observe"}},
			{name: "observe ACP pair, the candidate observes the ACP agent's connector", acpMode: "observe",
				connectors: map[string]string{"kiro": "observe"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				api := newAPI(t, "action", tc.connectors, tc.acpMode)
				frame := `{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{"sessionId":"s","prompt":[{"type":"text","text":"hello"}]}}`
				body, err := json.Marshal(acp.Evaluation{
					Profile: "default", Mode: acp.Mode(tc.acpMode), AgentID: "kiro", ClientID: "zed",
					Direction: acp.ClientToAgent, Surface: acp.SurfacePrompt, Method: "session/prompt", Payload: json.RawMessage(frame),
				})
				if err != nil {
					t.Fatal(err)
				}
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, "/api/v1/acp/evaluate", bytes.NewReader(body))
				api.handleACPEvaluate(rec, req.WithContext(context.WithValue(req.Context(), testVerifiedSubjectKey{}, unknown)))
				var verdict acp.Verdict
				if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &verdict) != nil {
					t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
				}
				if (verdict.Action == "block") != tc.block || verdict.WouldBlock != tc.wouldBlock ||
					strings.Contains(verdict.Reason, fact) != tc.refused {
					t.Fatalf("verdict %+v; want block %t, would_block %t, the fact named %t", verdict, tc.block, tc.wouldBlock, tc.refused)
				}
			})
		}
	})

	t.Run("inspect tool with an unscoped credential", func(t *testing.T) {
		for _, tc := range []struct {
			name, global string
			connectors   map[string]string
			scoped       string
			refused      bool
		}{
			{name: "global strict action, the gateway's connector set to observe", global: "action", connectors: map[string]string{"openclaw": "observe"}},
			{name: "global observe, the gateway's connector in strict action", global: "observe", connectors: map[string]string{"openclaw": "action"}, refused: true},
			{name: "global strict action, a connector it does not set", global: "action", connectors: map[string]string{"codex": "observe"}, refused: true},
			{name: "a scoped credential keeps its own connector", global: "action", connectors: map[string]string{"openclaw": "observe"}, scoped: "codex", refused: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				api := newAPI(t, tc.global, tc.connectors, "observe")
				req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", strings.NewReader(`{"tool":"bash","args":{"command":"ls"}}`))
				ctx := context.WithValue(req.Context(), testVerifiedSubjectKey{}, unknown)
				if tc.scoped != "" {
					ctx = withAuthenticatedInspectConnector(ctx, tc.scoped)
				}
				rec := httptest.NewRecorder()
				api.guardrailProfileInspectMiddleware(http.HandlerFunc(api.handleInspectTool)).ServeHTTP(rec, req.WithContext(ctx))
				var verdict ToolInspectVerdict
				if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &verdict) != nil {
					t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
				}
				if refused := verdict.Action == "block" && strings.Contains(verdict.Reason, "DefenseClaw refused this request: "+fact); refused != tc.refused {
					t.Fatalf("verdict %+v; want refused %t", verdict, tc.refused)
				}
			})
		}
	})
}
