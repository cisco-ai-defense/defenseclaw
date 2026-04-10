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

// Package connector defines the Connector interface and RoutingDecision type
// that allow the guardrail proxy to support multiple agent frameworks
// (OpenClaw, ZeptoClaw, future frameworks) through a single HTTP server.
//
// Each Connector translates framework-specific HTTP requests into a canonical
// RoutingDecision that the proxy core processes uniformly.
package connector

import (
	"net/http"
)

// RoutingDecision is the canonical output every connector produces. It contains
// everything the proxy core needs to forward the request to the upstream LLM
// provider and inspect it.
type RoutingDecision struct {
	// UpstreamURL is the full upstream URL (e.g. https://api.openai.com/v1/chat/completions).
	UpstreamURL string

	// ProviderName is the canonical provider name: "openai", "anthropic", "azure", etc.
	ProviderName string

	// APIKey is the real upstream API key extracted from the request.
	APIKey string

	// AuthHeader is the header name for upstream auth ("Authorization", "x-api-key", "api-key").
	AuthHeader string

	// AuthScheme is the prefix for the auth value ("Bearer" or "" for bare key).
	AuthScheme string

	// Model is the resolved model ID from the request body.
	Model string

	// Stream indicates whether SSE streaming was requested.
	Stream bool

	// RawBody is the original request body bytes.
	RawBody []byte

	// PassthroughMode indicates the request should be forwarded verbatim
	// (provider-native paths like /v1/messages for Anthropic).
	PassthroughMode bool

	// ExtraUpstreamHeaders are additional headers to set on the upstream request
	// (e.g. anthropic-version, x-goog-api-key).
	ExtraUpstreamHeaders map[string]string

	// ConnectorName identifies which connector produced this decision
	// ("openclaw", "zeptoclaw", "generic") — used for telemetry.
	ConnectorName string
}

// Connector translates framework-specific HTTP requests into a RoutingDecision.
// Each agent framework (OpenClaw, ZeptoClaw, etc.) has a dedicated Connector
// implementation.
type Connector interface {
	// Name returns the connector identifier (e.g. "openclaw", "zeptoclaw", "generic").
	Name() string

	// Detect returns true if this connector should handle the given request.
	// Connectors are checked in priority order; the first one returning true wins.
	Detect(r *http.Request) bool

	// Authenticate checks whether the request is authorized to use this connector.
	// Returns true if authentication passes.
	Authenticate(r *http.Request) bool

	// Route extracts routing information from the request and produces a
	// canonical RoutingDecision. The body parameter contains the already-read
	// request body bytes.
	Route(r *http.Request, body []byte) (*RoutingDecision, error)
}
