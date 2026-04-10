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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// OpenClawConnector handles requests from OpenClaw's fetch interceptor which
// sets X-DC-Target-URL and X-AI-Auth headers on every outbound LLM call.
type OpenClawConnector struct {
	// gatewayToken is the OPENCLAW_GATEWAY_TOKEN accepted in X-DC-Auth.
	gatewayToken string
	// masterKey is the deterministic key derived from device.key.
	masterKey string
}

// NewOpenClawConnector creates an OpenClaw connector with the given auth credentials.
func NewOpenClawConnector(gatewayToken, masterKey string) *OpenClawConnector {
	return &OpenClawConnector{
		gatewayToken: gatewayToken,
		masterKey:    masterKey,
	}
}

func (c *OpenClawConnector) Name() string { return "openclaw" }

// Detect returns true if the request has the X-DC-Target-URL header,
// which is set by OpenClaw's fetch interceptor.
func (c *OpenClawConnector) Detect(r *http.Request) bool {
	return r.Header.Get("X-DC-Target-URL") != ""
}

// Authenticate checks the request against:
//  1. X-DC-Auth token (gateway token set by the fetch interceptor)
//  2. Authorization with master key (sk-dc-*)
//  3. Loopback fallback (when no gateway token is configured)
//  4. No auth configured (initial state before setup)
func (c *OpenClawConnector) Authenticate(r *http.Request) bool {
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

	isLoopback := IsLoopback(r)

	// Loopback fallback: allow when no gatewayToken is configured (legacy / first-run).
	if isLoopback && c.gatewayToken == "" {
		return true
	}

	// No auth configured at all — proxy is open (initial state before setup).
	if c.gatewayToken == "" && c.masterKey == "" {
		return true
	}

	return false
}

// Route extracts routing information from OpenClaw's fetch interceptor headers:
//   - X-DC-Target-URL → upstream URL and provider inference
//   - X-AI-Auth → API key (normalized to "Bearer <key>" by the interceptor)
//
// For non-chat-completions paths, PassthroughMode is set to forward verbatim.
func (c *OpenClawConnector) Route(r *http.Request, body []byte) (*RoutingDecision, error) {
	targetURL := r.Header.Get("X-DC-Target-URL")
	if targetURL == "" {
		return nil, fmt.Errorf("connector: openclaw: missing X-DC-Target-URL header")
	}

	// SSRF protection: only forward to domains listed in providers.json.
	if !IsKnownProviderDomain(targetURL) {
		return nil, fmt.Errorf("connector: openclaw: target URL does not match any known LLM provider domain: %s", ScrubURLSecrets(targetURL))
	}

	providerName := InferProviderFromURL(targetURL)

	// Extract the real API key from X-AI-Auth (normalized by the fetch interceptor).
	apiKey := ""
	if aiAuth := r.Header.Get("X-AI-Auth"); strings.HasPrefix(aiAuth, "Bearer ") {
		apiKey = strings.TrimPrefix(aiAuth, "Bearer ")
	}

	// Determine auth header and scheme for the upstream provider.
	authHeader := "Authorization"
	authScheme := "Bearer"
	switch providerName {
	case "anthropic":
		authHeader = "x-api-key"
		authScheme = ""
	case "azure":
		authHeader = "api-key"
		authScheme = ""
	}

	// Extract model from body.
	var partial struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	_ = json.Unmarshal(body, &partial)

	// Determine if passthrough mode (non-chat-completions paths).
	passthrough := !strings.HasSuffix(r.URL.Path, "/chat/completions")

	// Build extra upstream headers (e.g. anthropic-version).
	extraHeaders := make(map[string]string)
	if v := r.Header.Get("anthropic-version"); v != "" {
		extraHeaders["anthropic-version"] = v
	}

	return &RoutingDecision{
		UpstreamURL:          targetURL,
		ProviderName:         providerName,
		APIKey:               apiKey,
		AuthHeader:           authHeader,
		AuthScheme:           authScheme,
		Model:                partial.Model,
		Stream:               partial.Stream,
		RawBody:              body,
		PassthroughMode:      passthrough,
		ExtraUpstreamHeaders: extraHeaders,
		ConnectorName:        "openclaw",
	}, nil
}
