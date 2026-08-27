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

import "context"

// ModelRouter is the interface for an embedded semantic router that selects
// the optimal LLM provider/model for each request based on content signals.
// The router slots into the proxy pipeline between pre-call guardrails and
// the upstream forward.
//
// Implementations must be safe for concurrent use and must never block the
// request path — if routing fails, return nil to fall through to the default
// provider resolution (X-DC-Target-URL / Bifrost).
type ModelRouter interface {
	// Route evaluates the request and returns a routing decision.
	// A nil return means "use the default path" (graceful degradation).
	Route(ctx context.Context, input *ModelRouterInput) *ModelRouterDecision
}

// ModelRouterInput carries the request data and guardrail signals needed
// for routing decisions. Populated by the proxy from the parsed ChatRequest
// and pre-call inspection verdict.
type ModelRouterInput struct {
	Model    string
	Messages []ChatMessage
	Stream   bool

	// Rich context fields for semantic routing.
	Tools          []interface{}
	SessionID      string
	ConversationID string
	UserID         string
	UserGroups     []string
	Headers        map[string]string
	Metadata       map[string]interface{}
	RequestModel   string
}

// ModelRouterDecision is the routing outcome. The proxy uses these fields
// to override the target URL, model, and API key before forwarding upstream.
type ModelRouterDecision struct {
	// Provider is the gateway provider family for Model (for example
	// "ollama" or "openai"). The classifier returns only an alias; this
	// value comes from the gateway-owned backend catalog.
	Provider string

	// TargetURL overrides X-DC-Target-URL (provider base URL).
	TargetURL string
	// TargetURLOverride distinguishes clearing the connector's original
	// upstream from keeping it. Every resolved backend sets this so a route to
	// a different provider cannot accidentally reuse the original endpoint.
	TargetURLOverride bool

	// Model overrides the model in the request body.
	Model string

	// APIKey is the resolved credential for the selected provider.
	// Empty means keep the existing key unless APIKeyOverride is true.
	APIKey string
	// APIKeyOverride distinguishes "clear the original provider credential"
	// from "keep the original credential". Router-selected base URLs must set
	// this even for keyless local backends so credentials are never forwarded
	// across provider trust boundaries.
	APIKeyOverride bool

	// Reason is a human-readable explanation for observability.
	Reason string
}

// ModelRouterBackend is the gateway-owned forwarding target for one model
// alias returned by the semantic router. Credentials stay in DefenseClaw and
// are never sent to the classifier.
type ModelRouterBackend struct {
	Name      string
	Provider  string
	Model     string
	BaseURL   string
	APIKeyEnv string
}

// SetModelRouter installs an embedded model router into the proxy.
// When set, the proxy calls Route() after pre-call guardrails pass and
// before forwarding to the upstream provider. A nil router disables
// semantic routing (the proxy uses its default path).
func (p *GuardrailProxy) SetModelRouter(mr ModelRouter) {
	p.modelRouter = mr
}
