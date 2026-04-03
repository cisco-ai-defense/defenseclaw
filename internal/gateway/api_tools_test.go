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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

func testAPIForTools(t *testing.T) *APIServer {
	t.Helper()
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	// client is nil — no websocket connection
	return NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
}

func testAPIForToolsWithToken(t *testing.T, token string) (*APIServer, http.Handler) {
	t.Helper()
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Gateway.Token = token
	cfg.Guardrail.Mode = "action"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/tools/register", api.handleToolRegister)
	mux.HandleFunc("/api/v1/tools/catalog", api.handleToolCatalogV1)
	mux.HandleFunc("/api/v1/tools/unregister", api.handleToolUnregister)
	mux.HandleFunc("/skills", api.handleSkills)
	mux.HandleFunc("/mcps", api.handleMCPs)
	handler := api.tokenAuth(csrfProtect(mux))
	return api, handler
}

// ---------------------------------------------------------------------------
// POST /api/v1/tools/register — valid payload
// ---------------------------------------------------------------------------

func TestToolRegister_ValidPayload(t *testing.T) {
	api := testAPIForTools(t)

	body := `{
		"platform": "testplatform",
		"tools": [
			{"name": "Bash", "type": "builtin", "description": "Execute shell commands", "risk_level": "high"},
			{"name": "mcp__test__send", "type": "mcp", "source": "testplatform", "description": "Send message"}
		]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tools/register",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Client", "test")
	w := httptest.NewRecorder()
	api.handleToolRegister(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", w.Result().StatusCode, http.StatusOK, w.Body.String())
	}

	var resp map[string]int
	if err := json.NewDecoder(w.Result().Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["registered"] != 2 {
		t.Errorf("registered = %d, want 2", resp["registered"])
	}
}

// ---------------------------------------------------------------------------
// POST /api/v1/tools/register — empty tools array returns 400
// ---------------------------------------------------------------------------

func TestToolRegister_EmptyTools(t *testing.T) {
	api := testAPIForTools(t)

	body := `{"platform": "testplatform", "tools": []}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tools/register",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Client", "test")
	w := httptest.NewRecorder()
	api.handleToolRegister(w, req)

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Result().StatusCode, http.StatusBadRequest)
	}
}

// ---------------------------------------------------------------------------
// POST /api/v1/tools/register — missing platform returns 400
// ---------------------------------------------------------------------------

func TestToolRegister_MissingPlatform(t *testing.T) {
	api := testAPIForTools(t)

	body := `{"tools": [{"name": "Bash", "type": "builtin"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tools/register",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Client", "test")
	w := httptest.NewRecorder()
	api.handleToolRegister(w, req)

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Result().StatusCode, http.StatusBadRequest)
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/tools/catalog — returns registered tools
// ---------------------------------------------------------------------------

func TestToolCatalogV1_ReturnsRegisteredTools(t *testing.T) {
	api := testAPIForTools(t)

	// Register some tools first
	registerTestTools(t, api, "plat1", []toolRegisterEntry{
		{Name: "Bash", Type: "builtin", Description: "Shell"},
		{Name: "Read", Type: "builtin", Description: "Read files"},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tools/catalog", nil)
	w := httptest.NewRecorder()
	api.handleToolCatalogV1(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Result().StatusCode, http.StatusOK)
	}

	var resp struct {
		Tools     []audit.RegisteredTool `json:"tools"`
		Count     int                    `json:"count"`
		Platforms []string               `json:"platforms"`
	}
	if err := json.NewDecoder(w.Result().Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Count != 2 {
		t.Errorf("count = %d, want 2", resp.Count)
	}
	if len(resp.Tools) != 2 {
		t.Errorf("len(tools) = %d, want 2", len(resp.Tools))
	}
	if len(resp.Platforms) != 1 || resp.Platforms[0] != "plat1" {
		t.Errorf("platforms = %v, want [plat1]", resp.Platforms)
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/tools/catalog?platform= — filters by platform
// ---------------------------------------------------------------------------

func TestToolCatalogV1_FiltersByPlatform(t *testing.T) {
	api := testAPIForTools(t)

	registerTestTools(t, api, "alpha", []toolRegisterEntry{
		{Name: "Bash", Type: "builtin"},
	})
	registerTestTools(t, api, "beta", []toolRegisterEntry{
		{Name: "Read", Type: "builtin"},
		{Name: "Write", Type: "builtin"},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tools/catalog?platform=beta", nil)
	w := httptest.NewRecorder()
	api.handleToolCatalogV1(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Result().StatusCode, http.StatusOK)
	}

	var resp struct {
		Tools     []audit.RegisteredTool `json:"tools"`
		Count     int                    `json:"count"`
		Platforms []string               `json:"platforms"`
	}
	if err := json.NewDecoder(w.Result().Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Count != 2 {
		t.Errorf("count = %d, want 2", resp.Count)
	}
	for _, tool := range resp.Tools {
		if tool.Platform != "beta" {
			t.Errorf("tool %q has platform %q, want beta", tool.Name, tool.Platform)
		}
	}
}

// ---------------------------------------------------------------------------
// DELETE /api/v1/tools/unregister — removes tools
// ---------------------------------------------------------------------------

func TestToolUnregister_RemovesTools(t *testing.T) {
	api := testAPIForTools(t)

	registerTestTools(t, api, "plat1", []toolRegisterEntry{
		{Name: "Bash", Type: "builtin"},
		{Name: "Read", Type: "builtin"},
		{Name: "Write", Type: "builtin"},
	})

	body := `{"platform": "plat1", "names": ["Bash", "Write"]}`
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tools/unregister",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Client", "test")
	w := httptest.NewRecorder()
	api.handleToolUnregister(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", w.Result().StatusCode, http.StatusOK, w.Body.String())
	}

	var resp map[string]int
	if err := json.NewDecoder(w.Result().Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["unregistered"] != 2 {
		t.Errorf("unregistered = %d, want 2", resp["unregistered"])
	}

	// Verify only Read remains
	catalogReq := httptest.NewRequest(http.MethodGet, "/api/v1/tools/catalog?platform=plat1", nil)
	catalogW := httptest.NewRecorder()
	api.handleToolCatalogV1(catalogW, catalogReq)

	var catalogResp struct {
		Count int `json:"count"`
	}
	if err := json.NewDecoder(catalogW.Result().Body).Decode(&catalogResp); err != nil {
		t.Fatalf("decode catalog: %v", err)
	}
	if catalogResp.Count != 1 {
		t.Errorf("remaining tools = %d, want 1", catalogResp.Count)
	}
}

// ---------------------------------------------------------------------------
// GET /skills — falls back to registered skills when client is nil
// ---------------------------------------------------------------------------

func TestSkills_FallbackToRegistered(t *testing.T) {
	api := testAPIForTools(t)

	registerTestTools(t, api, "plat1", []toolRegisterEntry{
		{Name: "my_skill", Type: "skill", Description: "A skill"},
		{Name: "Bash", Type: "builtin", Description: "Shell"},
		{Name: "mcp__test", Type: "mcp", Description: "MCP tool"},
	})

	req := httptest.NewRequest(http.MethodGet, "/skills", nil)
	w := httptest.NewRecorder()
	api.handleSkills(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", w.Result().StatusCode, http.StatusOK, w.Body.String())
	}

	var skills []audit.RegisteredTool
	if err := json.NewDecoder(w.Result().Body).Decode(&skills); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(skills) != 1 {
		t.Fatalf("len(skills) = %d, want 1", len(skills))
	}
	if skills[0].Name != "my_skill" {
		t.Errorf("skill name = %q, want my_skill", skills[0].Name)
	}
	if skills[0].Type != "skill" {
		t.Errorf("skill type = %q, want skill", skills[0].Type)
	}
}

// ---------------------------------------------------------------------------
// GET /mcps — falls back to registered MCPs when client is nil
// ---------------------------------------------------------------------------

func TestMCPs_FallbackToRegistered(t *testing.T) {
	api := testAPIForTools(t)

	registerTestTools(t, api, "plat1", []toolRegisterEntry{
		{Name: "mcp__nanoclaw__send", Type: "mcp", Source: "nanoclaw", Description: "Send"},
		{Name: "Bash", Type: "builtin", Description: "Shell"},
		{Name: "my_skill", Type: "skill", Description: "A skill"},
	})

	req := httptest.NewRequest(http.MethodGet, "/mcps", nil)
	w := httptest.NewRecorder()
	api.handleMCPs(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", w.Result().StatusCode, http.StatusOK, w.Body.String())
	}

	var mcps []audit.RegisteredTool
	if err := json.NewDecoder(w.Result().Body).Decode(&mcps); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(mcps) != 1 {
		t.Fatalf("len(mcps) = %d, want 1", len(mcps))
	}
	if mcps[0].Name != "mcp__nanoclaw__send" {
		t.Errorf("mcp name = %q, want mcp__nanoclaw__send", mcps[0].Name)
	}
	if mcps[0].Type != "mcp" {
		t.Errorf("mcp type = %q, want mcp", mcps[0].Type)
	}
}

// ---------------------------------------------------------------------------
// Auth: token auth required on tool registration endpoints
// ---------------------------------------------------------------------------

func TestToolRegister_AuthRequired(t *testing.T) {
	_, handler := testAPIForToolsWithToken(t, "secret-token-abc")

	body := `{
		"platform": "testplatform",
		"tools": [{"name": "Bash", "type": "builtin"}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tools/register",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Client", "test")
	// No token header
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Result().StatusCode, http.StatusUnauthorized)
	}
}

func TestToolRegister_AuthWithValidToken(t *testing.T) {
	_, handler := testAPIForToolsWithToken(t, "secret-token-abc")

	body := `{
		"platform": "testplatform",
		"tools": [{"name": "Bash", "type": "builtin"}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tools/register",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Client", "test")
	req.Header.Set("X-DefenseClaw-Token", "secret-token-abc")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d; body = %s", w.Result().StatusCode, http.StatusOK, w.Body.String())
	}
}

func TestToolUnregister_AuthRequired(t *testing.T) {
	_, handler := testAPIForToolsWithToken(t, "secret-token-abc")

	body := `{"platform": "testplatform", "names": ["Bash"]}`
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tools/unregister",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Client", "test")
	// No token header
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Result().StatusCode, http.StatusUnauthorized)
	}
}

func TestToolCatalogV1_AuthRequired(t *testing.T) {
	_, handler := testAPIForToolsWithToken(t, "secret-token-abc")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tools/catalog", nil)
	// No token header — GET is exempt from CSRF but token auth still applies
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Result().StatusCode, http.StatusUnauthorized)
	}
}

// ---------------------------------------------------------------------------
// POST /api/v1/tools/register — upsert overwrites existing entry
// ---------------------------------------------------------------------------

func TestToolRegister_Upsert(t *testing.T) {
	api := testAPIForTools(t)

	// Register initial
	registerTestTools(t, api, "plat1", []toolRegisterEntry{
		{Name: "Bash", Type: "builtin", Description: "Old description", RiskLevel: "low"},
	})

	// Register again with updated fields
	registerTestTools(t, api, "plat1", []toolRegisterEntry{
		{Name: "Bash", Type: "builtin", Description: "New description", RiskLevel: "high"},
	})

	// Verify only one entry exists with updated description
	catalogReq := httptest.NewRequest(http.MethodGet, "/api/v1/tools/catalog?platform=plat1", nil)
	w := httptest.NewRecorder()
	api.handleToolCatalogV1(w, catalogReq)

	var resp struct {
		Tools []audit.RegisteredTool `json:"tools"`
		Count int                    `json:"count"`
	}
	if err := json.NewDecoder(w.Result().Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Count != 1 {
		t.Fatalf("count = %d, want 1 (upsert should not duplicate)", resp.Count)
	}
	if resp.Tools[0].Description != "New description" {
		t.Errorf("description = %q, want %q", resp.Tools[0].Description, "New description")
	}
	if resp.Tools[0].RiskLevel != "high" {
		t.Errorf("risk_level = %q, want %q", resp.Tools[0].RiskLevel, "high")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func registerTestTools(t *testing.T, api *APIServer, platform string, tools []toolRegisterEntry) {
	t.Helper()
	reqBody := toolRegisterRequest{
		Platform: platform,
		Tools:    tools,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("marshal register request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tools/register",
		bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Client", "test")
	w := httptest.NewRecorder()
	api.handleToolRegister(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("register tools failed: status=%d body=%s", w.Result().StatusCode, w.Body.String())
	}
}
