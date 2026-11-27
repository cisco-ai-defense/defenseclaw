// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// rel-1-0-10:GAP-2181, a documented limit: a Bedrock ConverseStream has no
// content-free event, so while signed reasoning ends in a run still being
// checked and the model is quiet, the client gets no bytes until the
// reasoning resumes or the message ends. The signed reasoning frames stay
// byte-identical (TestGAP2170SignedReasoningWireUnchanged) and are never
// masked. InvokeModelWithResponseStream for an Anthropic model does have one
// (the Anthropic ping in a chunk frame). If Converse ever gets a keep-alive,
// change this pin and the docs line in get-started/unified-llm-key.mdx.
func TestConverseStreamHasNoKeepAliveDocumentedLimit(t *testing.T) {
	const model = "anthropic.claude-sonnet-4-5-20250929-v1:0"
	converse := &passthroughStream{model: model, bedrock: &bedrockEventStreamText{converse: true, model: model}}
	if got := converse.keepAlive(true); got != nil {
		t.Fatalf("Converse keep-alive = %q, want none (documented limit)", got)
	}
	invoke := &passthroughStream{model: model, bedrock: &bedrockEventStreamText{model: model}}
	if invoke.keepAlive(true) == nil {
		t.Fatal("InvokeModelWithResponseStream for an Anthropic model lost its ping keep-alive")
	}
}
