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

package connector

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
)

// OpenClawConnector handles LLM traffic routing and tool inspection for OpenClaw.
// LLM traffic: fetch interceptor plugin patches globalThis.fetch to route
// through the proxy using X-DC-Target-URL and X-AI-Auth headers.
// Tool inspection: same plugin hooks api.on("before_tool_call") and calls
// /api/v1/inspect/tool.
type OpenClawConnector struct {
	gatewayToken string
	masterKey    string
}

// NewOpenClawConnector creates a new OpenClaw connector.
func NewOpenClawConnector() *OpenClawConnector {
	return &OpenClawConnector{}
}

func (c *OpenClawConnector) Name() string        { return "openclaw" }
func (c *OpenClawConnector) Description() string  { return "fetch interceptor plugin" }
func (c *OpenClawConnector) ToolInspectionMode() ToolInspectionMode { return ToolModeBoth }
func (c *OpenClawConnector) SubprocessPolicy() SubprocessPolicy {
	return ResolveSubprocessPolicy(SubprocessSandbox)
}

func (c *OpenClawConnector) Setup(ctx context.Context, opts SetupOpts) error {
	// Surface 3: Plugin subprocess enforcement
	policy := ResolveSubprocessPolicy(SubprocessSandbox)
	if err := SetupSubprocessEnforcement(policy, opts); err != nil {
		return fmt.Errorf("openclaw subprocess enforcement: %w", err)
	}

	// Write hook script for tool inspection
	hookDir := filepath.Join(opts.DataDir, "hooks")
	if err := WriteHookScript(hookDir, opts.APIAddr); err != nil {
		return fmt.Errorf("openclaw hook script: %w", err)
	}

	return nil
}

func (c *OpenClawConnector) Teardown(ctx context.Context, opts SetupOpts) error {
	TeardownSubprocessEnforcement(opts)
	return nil
}

func (c *OpenClawConnector) Authenticate(r *http.Request) bool {
	isLoopback := IsLoopback(r)

	// Check X-DC-Auth token (set by the fetch interceptor).
	if dcAuth := r.Header.Get("X-DC-Auth"); dcAuth != "" {
		token := strings.TrimPrefix(dcAuth, "Bearer ")
		if c.gatewayToken != "" && token == c.gatewayToken {
			return true
		}
	}

	// Check Authorization with the proxy master key.
	if c.masterKey != "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") && strings.TrimPrefix(auth, "Bearer ") == c.masterKey {
			return true
		}
	}

	// Loopback fallback: allow when no gatewayToken is configured.
	if isLoopback && c.gatewayToken == "" {
		return true
	}

	// No auth configured at all — proxy is open (initial state).
	if c.gatewayToken == "" && c.masterKey == "" {
		return true
	}

	return false
}

// SetCredentials injects the gateway token and master key at sidecar boot.
func (c *OpenClawConnector) SetCredentials(gatewayToken, masterKey string) {
	c.gatewayToken = gatewayToken
	c.masterKey = masterKey
}

func (c *OpenClawConnector) Route(r *http.Request, body []byte) (*ConnectorSignals, error) {
	cs := &ConnectorSignals{
		ConnectorName: "openclaw",
		StripHeaders: []string{
			"X-DC-Target-URL", "X-DC-Auth", "X-AI-Auth",
		},
	}

	// X-DC-Target-URL is set by the plugin's fetch interceptor.
	cs.RawUpstream = r.Header.Get("X-DC-Target-URL")

	// X-AI-Auth carries the real provider API key.
	if aiAuth := r.Header.Get("X-AI-Auth"); strings.HasPrefix(aiAuth, "Bearer ") {
		cs.RawAPIKey = strings.TrimPrefix(aiAuth, "Bearer ")
	} else {
		cs.RawAPIKey = ExtractAPIKey(r)
	}

	cs.RawBody = body
	cs.RawModel = ParseModelFromBody(body)
	cs.Stream = ParseStreamFromBody(body)

	// Non-chat paths (Bedrock SigV4, embeddings, etc.) are passthrough.
	if !isChatPath(r.URL.Path) {
		cs.PassthroughMode = true
	}

	return cs, nil
}


