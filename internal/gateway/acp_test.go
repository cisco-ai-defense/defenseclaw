// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestACPEvaluateDeniedMethodHonorsProfileMode(t *testing.T) {
	for _, mode := range []string{"observe", "action"} {
		t.Run(mode, func(t *testing.T) {
			cfg := &config.Config{ACP: config.ACPConfig{
				Enabled: true, Mode: mode, DefaultProfile: "default",
				Clients: map[string]config.ACPBinding{"zed": {Enabled: true, Profile: "default"}},
				Agents:  map[string]config.ACPBinding{"kiro": {Enabled: true, Profile: "default"}},
				Profiles: map[string]config.ACPProfile{"default": {
					Mode: mode, AllowedClients: []string{"zed"}, AllowedAgents: []string{"kiro"},
					DeniedMethods: []string{"terminal/create"},
				}},
			}}
			payload := json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"terminal/create","params":{"sessionId":"s","command":"false","args":[]}}`)
			body, err := json.Marshal(acp.Evaluation{Profile: "default", Mode: acp.Mode(mode), AgentID: "kiro", ClientID: "zed", Direction: acp.AgentToClient, Surface: acp.SurfaceTerminal, Method: "terminal/create", Payload: payload})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/api/v1/acp/evaluate", bytes.NewReader(body))
			response := httptest.NewRecorder()
			(&APIServer{scannerCfg: cfg}).handleACPEvaluate(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			var verdict acp.Verdict
			if err := json.Unmarshal(response.Body.Bytes(), &verdict); err != nil {
				t.Fatal(err)
			}
			if mode == "action" && verdict.Action != "block" {
				t.Fatalf("action verdict=%+v", verdict)
			}
			if mode == "observe" && (verdict.Action != "allow" || !verdict.WouldBlock || verdict.RawAction != "block") {
				t.Fatalf("observe verdict=%+v", verdict)
			}
		})
	}
}

func TestACPEvaluateRequiresEnabledProfilePinnedBindings(t *testing.T) {
	base := config.ACPConfig{
		Enabled: true, DefaultProfile: "default",
		Clients: map[string]config.ACPBinding{"zed": {Enabled: true, Profile: "default"}},
		Agents:  map[string]config.ACPBinding{"kiro": {Enabled: true, Profile: "default"}},
		Profiles: map[string]config.ACPProfile{"default": {
			Mode: "action", AllowedClients: []string{"zed"}, AllowedAgents: []string{"kiro"},
			DeniedMethods: []string{"terminal/create"},
		}},
	}
	payload := json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"terminal/create","params":{}}`)
	body, _ := json.Marshal(acp.Evaluation{Profile: "default", Mode: acp.ModeAction, AgentID: "kiro", ClientID: "zed", Direction: acp.AgentToClient, Surface: acp.SurfaceTerminal, Method: "terminal/create", Payload: payload})
	tests := map[string]func(*config.ACPConfig){
		"missing client":   func(c *config.ACPConfig) { delete(c.Clients, "zed") },
		"disabled agent":   func(c *config.ACPConfig) { c.Agents["kiro"] = config.ACPBinding{Profile: "default"} },
		"profile mismatch": func(c *config.ACPConfig) { c.Clients["zed"] = config.ACPBinding{Enabled: true, Profile: "other"} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := base
			cfg.Clients = maps.Clone(base.Clients)
			cfg.Agents = maps.Clone(base.Agents)
			mutate(&cfg)
			response := httptest.NewRecorder()
			(&APIServer{scannerCfg: &config.Config{ACP: cfg}}).handleACPEvaluate(response,
				httptest.NewRequest(http.MethodPost, "/api/v1/acp/evaluate", bytes.NewReader(body)))
			if response.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestACPEvaluateRejectsRuntimeModeDrift(t *testing.T) {
	cfg := &config.Config{ACP: config.ACPConfig{
		Enabled: true, Mode: "action", DefaultProfile: "default",
		Clients: map[string]config.ACPBinding{"zed": {Enabled: true, Profile: "default"}},
		Agents:  map[string]config.ACPBinding{"kiro": {Enabled: true, Profile: "default"}},
		Profiles: map[string]config.ACPProfile{"default": {
			Mode: "action", AllowedClients: []string{"zed"}, AllowedAgents: []string{"kiro"},
		}},
	}}
	payload := json.RawMessage(`{"jsonrpc":"2.0","method":"initialized"}`)
	body, _ := json.Marshal(acp.Evaluation{
		Profile: "default", Mode: acp.ModeObserve, AgentID: "kiro", ClientID: "zed",
		Direction: acp.ClientToAgent, Surface: acp.SurfaceProtocol, Method: "initialized", Payload: payload,
	})
	response := httptest.NewRecorder()
	(&APIServer{scannerCfg: cfg}).handleACPEvaluate(response,
		httptest.NewRequest(http.MethodPost, "/api/v1/acp/evaluate", bytes.NewReader(body)))
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestACPEvaluateRejectsEnvelopeMetadataMismatch(t *testing.T) {
	cfg := &config.Config{ACP: config.ACPConfig{Enabled: true, Profiles: map[string]config.ACPProfile{"default": {}}}}
	payload := json.RawMessage(`{"jsonrpc":"2.0","method":"session/update","params":{}}`)
	body, _ := json.Marshal(acp.Evaluation{Profile: "default", AgentID: "kiro", ClientID: "zed", Direction: acp.AgentToClient, Surface: acp.SurfacePrompt, Method: "session/update", Payload: payload})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/acp/evaluate", bytes.NewReader(body))
	response := httptest.NewRecorder()
	(&APIServer{scannerCfg: cfg}).handleACPEvaluate(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestACPEvaluateRejectsTamperedCompletedTurnMetadata(t *testing.T) {
	payload, err := acp.BuildTurnEvaluationPayload([]json.RawMessage{
		json.RawMessage(`{"jsonrpc":"2.0","method":"session/update","params":{"update":{"content":{"text":"safe"}}}}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	payload = bytes.Replace(payload, []byte(`"safe"`), []byte(`"fake"`), 1)
	body, err := json.Marshal(acp.Evaluation{
		Profile: "default", Mode: acp.ModeAction, AgentID: "kiro", ClientID: "zed",
		Direction: acp.AgentToClient, Surface: acp.SurfaceOutput, Method: "session/update",
		Payload: payload, Aggregate: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	(&APIServer{scannerCfg: &config.Config{ACP: config.ACPConfig{Enabled: true}}}).handleACPEvaluate(
		response,
		httptest.NewRequest(http.MethodPost, "/api/v1/acp/evaluate", bytes.NewReader(body)),
	)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestACPEvaluateRejectsManagedRequestWithoutCredential(t *testing.T) {
	cfg := &config.Config{
		DataDir: t.TempDir(), DeploymentMode: "managed_enterprise",
		ACP: config.ACPConfig{
			Enabled: true, Mode: "action", DefaultProfile: "locked",
			Clients: map[string]config.ACPBinding{"zed": {Enabled: true, Profile: "locked"}},
			Agents:  map[string]config.ACPBinding{"kiro": {Enabled: true, Profile: "locked"}},
			Profiles: map[string]config.ACPProfile{"locked": {
				Mode: "action", AllowedClients: []string{"zed"}, AllowedAgents: []string{"kiro"},
			}},
		},
	}
	payload := json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{}}`)
	body, err := json.Marshal(acp.Evaluation{
		ClientID: "zed", AgentID: "kiro", Profile: "locked", Mode: acp.ModeAction,
		Direction: acp.ClientToAgent, Surface: acp.SurfacePrompt, Method: "session/prompt", Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	(&APIServer{scannerCfg: cfg}).handleACPEvaluate(
		response,
		httptest.NewRequest(http.MethodPost, "/api/v1/acp/evaluate", bytes.NewReader(body)),
	)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want 403; body=%s", response.Code, response.Body.String())
	}
}

func TestACPScopedTokenRequiresPrivateRegularFile(t *testing.T) {
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, "acp", ".token")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("scoped-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	api := &APIServer{scannerCfg: &config.Config{DataDir: dataDir}}
	if !api.acpAPITokenMatches("scoped-token") || api.acpAPITokenMatches("wrong") {
		t.Fatal("scoped ACP token comparison failed")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if api.acpAPITokenMatches("scoped-token") {
			t.Fatal("group/world-readable ACP token was accepted")
		}
	}
}

func TestACPReadinessCachesOnlyHealthProbe(t *testing.T) {
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, "acp", ".token")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("scoped-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	api := &APIServer{scannerCfg: &config.Config{DataDir: dataDir}}
	if !api.acpScopedTokenReady() {
		t.Fatal("fresh private token was not ready")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if !api.acpScopedTokenReady() {
		t.Fatal("readiness result was not cached")
	}
	api.acpReadinessCheckedAt = time.Now().Add(-time.Second)
	if api.acpScopedTokenReady() {
		t.Fatal("expired readiness cache hid token removal")
	}
}

func TestACPEnterpriseCredentialPinsRequestBinding(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed credential authentication requires an installer-protected service tree on Windows")
	}
	dataDir := t.TempDir()
	credential, err := acp.EnsureEnterpriseCredential(dataDir, "uid:501", "zed", "kiro", "locked")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		DataDir: dataDir, DeploymentMode: "managed_enterprise",
		ACP: config.ACPConfig{
			Enabled: true, Mode: "action", DefaultProfile: "locked",
			Clients: map[string]config.ACPBinding{"zed": {Enabled: true, Profile: "locked"}},
			Agents:  map[string]config.ACPBinding{"kiro": {Enabled: true, Profile: "locked"}},
			Profiles: map[string]config.ACPProfile{"locked": {
				Mode: "action", AllowedClients: []string{"zed"}, AllowedAgents: []string{"kiro"},
				DeniedMethods: []string{"session/prompt"},
			}},
		},
	}
	api := &APIServer{scannerCfg: cfg}
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{}}`)
	evaluation, err := json.Marshal(acp.Evaluation{
		ClientID: "zed", AgentID: "kiro", Profile: "locked", Mode: acp.ModeAction, Direction: acp.ClientToAgent,
		Surface: acp.SurfacePrompt, Method: "session/prompt", Payload: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/acp/evaluate", bytes.NewReader(evaluation))
	authenticated, ok := api.authenticateACPToken(r, credential.Token)
	if !ok {
		t.Fatal("managed credential did not authenticate")
	}
	w := httptest.NewRecorder()
	api.handleACPEvaluate(w, authenticated)
	if w.Code != http.StatusOK {
		t.Fatalf("matching scope status = %d, body=%s", w.Code, w.Body.String())
	}

	var request acp.Evaluation
	if err := json.Unmarshal(evaluation, &request); err != nil {
		t.Fatal(err)
	}
	request.ClientID = "jetbrains"
	evaluation, _ = json.Marshal(request)
	w = httptest.NewRecorder()
	authenticated = httptest.NewRequest(http.MethodPost, "/api/v1/acp/evaluate", bytes.NewReader(evaluation))
	authenticated = authenticated.WithContext(withACPEnterpriseCredential(authenticated.Context(), credential))
	api.handleACPEvaluate(w, authenticated)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-binding scope status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

func TestACPSignedEvaluatorRoundTripNormal(t *testing.T) {
	dataDir := t.TempDir()
	token := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tokenPath := filepath.Join(dataDir, "acp", ".token")
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	api := &APIServer{scannerCfg: acpGatewayTestConfig(dataDir, "")}
	server := httptest.NewServer(api.tokenAuth(http.HandlerFunc(api.handleACPEvaluate)))
	defer server.Close()
	evaluator, err := acp.NewHTTPEvaluator(server.URL, token)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := evaluator.Evaluate(t.Context(), deniedACPTestEvaluation())
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Action != "block" {
		t.Fatalf("verdict = %+v, want block", verdict)
	}
}

func TestACPSignedEvaluatorRoundTripEnterprise(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed credential authentication requires an installer-protected service tree on Windows")
	}
	dataDir := t.TempDir()
	credential, err := acp.EnsureEnterpriseCredential(dataDir, "uid:501", "zed", "kiro", "locked")
	if err != nil {
		t.Fatal(err)
	}
	api := &APIServer{scannerCfg: acpGatewayTestConfig(dataDir, "managed_enterprise")}
	server := httptest.NewServer(api.tokenAuth(http.HandlerFunc(api.handleACPEvaluate)))
	defer server.Close()
	evaluator, err := acp.NewHTTPEvaluator(server.URL, credential.Token)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := evaluator.Evaluate(t.Context(), deniedACPTestEvaluation())
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Action != "block" {
		t.Fatalf("verdict = %+v, want block", verdict)
	}
}

func acpGatewayTestConfig(dataDir, deploymentMode string) *config.Config {
	return &config.Config{
		DataDir: dataDir, DeploymentMode: deploymentMode,
		ACP: config.ACPConfig{
			Enabled: true, Mode: "action", DefaultProfile: "locked",
			Clients: map[string]config.ACPBinding{"zed": {Enabled: true, Profile: "locked"}},
			Agents:  map[string]config.ACPBinding{"kiro": {Enabled: true, Profile: "locked"}},
			Profiles: map[string]config.ACPProfile{"locked": {
				Mode: "action", AllowedClients: []string{"zed"}, AllowedAgents: []string{"kiro"},
				DeniedMethods: []string{"session/prompt"},
			}},
		},
	}
}

func deniedACPTestEvaluation() acp.Evaluation {
	payload := json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{}}`)
	return acp.Evaluation{
		ClientID: "zed", AgentID: "kiro", Profile: "locked", Mode: acp.ModeAction,
		Direction: acp.ClientToAgent, Surface: acp.SurfacePrompt, Method: "session/prompt", Payload: payload,
	}
}
