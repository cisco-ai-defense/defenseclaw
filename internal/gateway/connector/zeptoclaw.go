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

// ZeptoClawConnector handles requests from ZeptoClaw where traffic is routed
// through the proxy via api_base config patching. ZeptoClaw sends standard
// HTTP with no DefenseClaw-specific headers (no X-DC-Target-URL).
//
// Detection: X-ZC-Provider header present, OR absence of X-DC-Target-URL
// combined with standard auth headers.
//
// Upstream URL resolution: uses config-provided provider map, falling back
// to the embedded ZeptoClawDefaultProviders table.
type ZeptoClawConnector struct {
	// gatewayToken is an optional proxy auth token accepted in X-DC-Auth.
	gatewayToken string
	// masterKey is the deterministic key derived from device.key.
	masterKey string
	// providers maps provider name → upstream entry (from config.yaml).
	// Falls back to ZeptoClawDefaultProviders for unknown providers.
	providers map[string]ZCProviderEntry
}

// NewZeptoClawConnector creates a ZeptoClaw connector.
// The providers map comes from config.yaml's guardrail.connectors.zeptoclaw.providers.
// If nil, only the embedded default table is used.
func NewZeptoClawConnector(gatewayToken, masterKey string, providers map[string]ZCProviderEntry) *ZeptoClawConnector {
	if providers == nil {
		providers = make(map[string]ZCProviderEntry)
	}
	return &ZeptoClawConnector{
		gatewayToken: gatewayToken,
		masterKey:    masterKey,
		providers:    providers,
	}
}

func (c *ZeptoClawConnector) Name() string { return "zeptoclaw" }

// Detect returns true if the request looks like it came from ZeptoClaw:
//   - Has X-ZC-Provider header (explicit hint), OR
//   - Does NOT have X-DC-Target-URL (not from OpenClaw) AND has standard auth headers.
func (c *ZeptoClawConnector) Detect(r *http.Request) bool {
	// Explicit ZeptoClaw header.
	if r.Header.Get("X-ZC-Provider") != "" {
		return true
	}

	// Not from OpenClaw (no X-DC-Target-URL) and has standard auth.
	if r.Header.Get("X-DC-Target-URL") == "" {
		if r.Header.Get("Authorization") != "" ||
			r.Header.Get("x-api-key") != "" ||
			r.Header.Get("api-key") != "" {
			return true
		}
	}

	return false
}

// Authenticate checks the request:
//  1. X-DC-Auth token (optional proxy auth)
//  2. Loopback trust (ZeptoClaw typically runs on same machine)
//  3. No auth configured (initial state)
func (c *ZeptoClawConnector) Authenticate(r *http.Request) bool {
	// Check X-DC-Auth token (optional proxy auth for ZeptoClaw).
	if dcAuth := r.Header.Get("X-DC-Auth"); dcAuth != "" {
		token := strings.TrimPrefix(dcAuth, "Bearer ")
		if c.gatewayToken != "" && token == c.gatewayToken {
			return true
		}
	}

	// Check Authorization with master key.
	if c.masterKey != "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") && strings.TrimPrefix(auth, "Bearer ") == c.masterKey {
			return true
		}
	}

	isLoopback := IsLoopback(r)

	// Loopback fallback: allow when no gatewayToken is configured.
	if isLoopback && c.gatewayToken == "" {
		return true
	}

	// No auth configured at all — proxy is open.
	if c.gatewayToken == "" && c.masterKey == "" {
		return true
	}

	return false
}

// Route resolves the upstream URL and provider from the request.
//
// Provider is determined by (in priority order):
//  1. X-ZC-Provider header (explicit hint from ZeptoClaw)
//  2. Model name prefix inference (gpt-* → openai, claude-* → anthropic)
//
// Upstream URL is resolved from:
//  1. X-ZC-Upstream header (optional, set by ZeptoClaw if configured)
//  2. Config-provided providers map (from setup command)
//  3. Embedded ZeptoClawDefaultProviders table (fallback)
func (c *ZeptoClawConnector) Route(r *http.Request, body []byte) (*RoutingDecision, error) {
	// Parse model and stream from body.
	var partial struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	_ = json.Unmarshal(body, &partial)

	// Resolve provider name.
	providerName := r.Header.Get("X-ZC-Provider")
	if providerName == "" {
		providerName = InferProviderFromModel(partial.Model)
	}
	if providerName == "" {
		return nil, fmt.Errorf("connector: zeptoclaw: cannot determine provider from model %q — set X-ZC-Provider header or use a known model prefix", partial.Model)
	}

	// Resolve upstream entry: config → defaults.
	entry, ok := c.providers[providerName]
	if !ok {
		entry, ok = ZeptoClawDefaultProviders[providerName]
		if !ok {
			return nil, fmt.Errorf("connector: zeptoclaw: unknown provider %q — add it to guardrail.connectors.zeptoclaw.providers in config.yaml", providerName)
		}
	}

	// Optional upstream URL override from header.
	upstreamURL := entry.UpstreamURL
	if hint := r.Header.Get("X-ZC-Upstream"); hint != "" {
		upstreamURL = hint
	}

	// Reconstruct full upstream URL by appending the request path.
	// ZeptoClaw sends to the proxy as e.g. POST /v1/chat/completions,
	// so we combine the base URL with the request path.
	fullUpstreamURL := strings.TrimRight(upstreamURL, "/") + r.URL.RequestURI()

	// Extract API key from standard auth headers.
	apiKey, _, _ := ExtractAPIKey(r, "sk-dc-")

	// Use the provider entry's auth header/scheme for upstream.
	authHeader := entry.AuthHeader
	authScheme := entry.AuthScheme
	if authHeader == "" {
		authHeader = "Authorization"
		authScheme = "Bearer"
	}

	return &RoutingDecision{
		UpstreamURL:          fullUpstreamURL,
		ProviderName:         providerName,
		APIKey:               apiKey,
		AuthHeader:           authHeader,
		AuthScheme:           authScheme,
		Model:                partial.Model,
		Stream:               partial.Stream,
		RawBody:              body,
		PassthroughMode:      false,
		ExtraUpstreamHeaders: make(map[string]string),
		ConnectorName:        "zeptoclaw",
	}, nil
}
