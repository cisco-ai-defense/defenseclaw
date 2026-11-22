// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
)

func TestRouteOnlyEndpointKnown(t *testing.T) {
	route := engine.Request{Listener: engine.ListenerRouteOnly, RequestedProvider: "openai"}
	for _, tc := range []struct {
		name string
		b    engine.Backend
		req  engine.Request
		want bool
	}{
		{"bedrock without base_url for a Responses call", engine.Backend{Provider: "bedrock"}, route, false},
		{"azure without base_url", engine.Backend{Provider: "azure"}, route, false},
		{"bedrock with its OpenAI-compatible base_url", engine.Backend{Provider: "bedrock", BaseURL: "https://bedrock-runtime.us-east-1.amazonaws.com/openai/v1"}, route, true},
		{"openai default endpoint", engine.Backend{Provider: "openai"}, route, true},
		{"anthropic default endpoint", engine.Backend{Provider: "Anthropic"}, route, true},
		{"bedrock on a Bedrock upstream (same provider)", engine.Backend{Provider: "bedrock"}, engine.Request{Listener: engine.ListenerRouteOnly, RequestedProvider: "bedrock"}, true},
		{"guardrail listener keeps every backend", engine.Backend{Provider: "bedrock"}, engine.Request{Listener: engine.ListenerGuardrail, RequestedProvider: "openai"}, true},
	} {
		if got := routeOnlyEndpointKnown(tc.b, tc.req); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}
