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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func validAgentDiscoveryBody() string {
	return `{
		"source": "cli",
		"scanned_at": "2026-05-04T18:21:00Z",
		"cache_hit": false,
		"duration_ms": 37,
		"agents": {
			"codex": {
				"installed": true,
				"has_config": true,
				"config_basename": "config.toml",
				"config_path_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"has_binary": true,
				"binary_basename": "codex",
				"binary_path_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				"version": "codex 1.2.3",
				"version_probe_status": "ok",
				"error_class": ""
			},
			"claudecode": {
				"installed": false,
				"has_config": false,
				"has_binary": false,
				"version_probe_status": "not_probed"
			}
		}
	}`
}

func TestAgentDiscoveryEndpoint_AcceptsSanitizedReport(t *testing.T) {
	api := &APIServer{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/discovery", strings.NewReader(validAgentDiscoveryBody()))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	api.handleAgentDiscovery(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%s", w.Code, w.Body.String())
	}
	var resp agentDiscoveryResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != "ok" || resp.Agents != 2 || resp.Installed != 1 {
		t.Fatalf("response=%+v want ok/2/1", resp)
	}
}

func TestAgentDiscoveryEndpoint_RejectsMalformedAndUnknownConnectors(t *testing.T) {
	api := &APIServer{}
	cases := []struct {
		name string
		body string
	}{
		{
			name: "malformed",
			body: `{not json`,
		},
		{
			name: "unknown connector",
			body: `{"source":"cli","scanned_at":"2026-05-04T18:21:00Z","agents":{"bogus":{"installed":true,"has_config":false,"has_binary":false}}}`,
		},
		{
			name: "raw path field rejected",
			body: `{"source":"cli","scanned_at":"2026-05-04T18:21:00Z","agents":{"codex":{"installed":true,"has_config":true,"has_binary":false,"config_path":"/Users/alice/.codex/config.toml"}}}`,
		},
		{
			name: "basename with slash rejected",
			body: `{"source":"cli","scanned_at":"2026-05-04T18:21:00Z","agents":{"codex":{"installed":true,"has_config":true,"config_basename":"alice/config.toml","has_binary":false}}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/discovery", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			api.handleAgentDiscovery(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d want 400 body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestAgentDiscoveryEndpoint_RejectsNonPOST(t *testing.T) {
	api := &APIServer{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/discovery", nil)
	w := httptest.NewRecorder()

	api.handleAgentDiscovery(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want 405", w.Code)
	}
}

func TestAgentDiscoveryEndpoint_UsesSidecarAuthAndCSRF(t *testing.T) {
	cfg := &config.Config{}
	cfg.Gateway.Token = "secret-token-123"
	api := &APIServer{scannerCfg: cfg}
	handler := api.tokenAuth(api.apiCSRFProtect(http.HandlerFunc(api.handleAgentDiscovery)))

	cases := []struct {
		name       string
		token      string
		client     string
		ct         string
		wantStatus int
	}{
		{name: "missing token", client: "python-cli", ct: "application/json", wantStatus: http.StatusUnauthorized},
		{name: "missing client header", token: "secret-token-123", ct: "application/json", wantStatus: http.StatusForbidden},
		{name: "wrong content type", token: "secret-token-123", client: "python-cli", ct: "text/plain", wantStatus: http.StatusUnsupportedMediaType},
		{name: "ok", token: "secret-token-123", client: "python-cli", ct: "application/json", wantStatus: http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/discovery", strings.NewReader(validAgentDiscoveryBody()))
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			if tc.client != "" {
				req.Header.Set("X-DefenseClaw-Client", tc.client)
			}
			if tc.ct != "" {
				req.Header.Set("Content-Type", tc.ct)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tc.wantStatus {
				t.Fatalf("status=%d want %d body=%s", w.Code, tc.wantStatus, w.Body.String())
			}
		})
	}
}
