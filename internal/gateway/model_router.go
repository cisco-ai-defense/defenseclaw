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

	// Pre-computed guardrail signals (zero-cost reuse).
	JailbreakScore float64
	PIIDetected    bool
	Severity       string

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
	// TargetURL overrides X-DC-Target-URL (provider base URL).
	TargetURL string

	// Model overrides the model in the request body.
	Model string

	// APIKey is the resolved credential for the selected provider.
	// Empty means keep the existing key resolution path.
	APIKey string

	// CacheHit indicates the response is served from semantic cache.
	// When true, CachedResponse contains the full response body.
	CacheHit       bool
	CachedResponse []byte

	// Reason is a human-readable explanation for observability.
	Reason string

	// Plugin-enriched fields from the semantic router.
	SystemPrompt       string
	ReasoningEffort    string
	UseReasoning       bool
	LoRAName           string
	HeaderMutations    *HeaderMutations
	RAGDocuments       []RAGDocument
	CompressedMessages []ChatMessage
	DecisionName       string
	Algorithm          string
	MatchedSignals     map[string]interface{}
	Warnings           []string
}

// HeaderMutations describes HTTP header changes the router wants applied
// to the upstream request.
type HeaderMutations struct {
	Add    []HeaderEntry `json:"add,omitempty"`
	Update []HeaderEntry `json:"update,omitempty"`
	Delete []string      `json:"delete,omitempty"`
}

// HeaderEntry is a single header name/value pair.
type HeaderEntry struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// RAGDocument represents a retrieved document returned by the router's
// RAG plugin for injection into the prompt context.
type RAGDocument struct {
	Content    string  `json:"content"`
	Source     string  `json:"source,omitempty"`
	Similarity float64 `json:"similarity,omitempty"`
}

// SetModelRouter installs an embedded model router into the proxy.
// When set, the proxy calls Route() after pre-call guardrails pass and
// before forwarding to the upstream provider. A nil router disables
// semantic routing (the proxy uses its default path).
func (p *GuardrailProxy) SetModelRouter(mr ModelRouter) {
	p.modelRouter = mr
}

// globalModelRouter holds a model router registered before the proxy is
// constructed. NewGuardrailProxy picks it up automatically.
// Safe without synchronization: written once during startup (before serving)
// and read-only thereafter.
var globalModelRouter ModelRouter

// RegisterModelRouter registers a model router globally. The proxy picks
// it up during construction (NewGuardrailProxy). Must be called during
// startup before the proxy begins serving requests.
func RegisterModelRouter(mr ModelRouter) {
	globalModelRouter = mr
}
