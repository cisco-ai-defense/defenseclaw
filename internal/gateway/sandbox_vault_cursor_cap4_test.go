// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/vault"
)

// Cursor answers a block of stop or subagentStop with a followup message,
// which starts a new turn: a capture on them never answers block, even
// when another rule blocked, so the hook renders no followup message.
func TestApplySandboxVaultCaptureCursorStopNeverBlocks(t *testing.T) {
	f := newSandboxIngressFixture(t)
	ctx := context.Background()
	profile := f.api.hookProfileForRequest(ctx, "cursor")
	for _, event := range []string{"stop", "subagentStop"} {
		c := &sandboxVaultCapture{Connector: "cursor", Event: event, Entries: []vault.Entry{{Name: "STRIPE_API_KEY", Exposed: true}}}
		resp := f.api.applySandboxVaultCapture(ctx, profile, agentHookRequest{ConnectorName: "cursor", HookEventName: event},
			[]byte(`{}`), map[string]interface{}{}, agentHookResponse{Action: "block", RawAction: "block", Mode: "action", Reason: "another rule"}, c)
		if resp.Action == "block" || !resp.WouldBlock || len(resp.HookOutput) != 0 {
			t.Fatalf("%s answer = %+v", event, resp)
		}
	}
}
