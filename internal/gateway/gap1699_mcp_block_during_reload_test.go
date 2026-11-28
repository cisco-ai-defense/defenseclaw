// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// gap1699Config is the default-tier Codex config, with the server blocked
// when blocked is set (defenseclaw mcp block <name> --connector codex).
func gap1699Config(blocked bool) *config.Config {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	if blocked {
		cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{Name: "dcc1699", Connector: "codex"}}
	}
	return cfg
}

// gap1699Reload starts a config write the gateway applies after delay: the
// gate is held as the config watcher holds it from the file event, then
// apply publishes the new config and the gate settles.
func gap1699Reload(t *testing.T, delay time.Duration, apply func()) {
	t.Helper()
	configReloadInFlight.begin()
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(delay)
		apply()
		configReloadInFlight.settle()
	}()
	t.Cleanup(func() { <-done })
}

func gap1699Call(api *APIServer, ctx context.Context, server string) codexHookResponse {
	return api.evaluateCodexHook(ctx, codexHookRequest{HookEventName: "PreToolUse",
		ToolName: "mcp__" + server + "__x", ToolInput: map[string]interface{}{}, CWD: "/work/p1699"})
}

// TestGAP1699BlockWrittenWhileAdmissionPendingRefusesTheFirstCall: after
// defenseclaw mcp set X and mcp block X, the first Codex PreToolUse of X was
// allowed ("still scanning ... allowed while admission is pending") because
// the block was still being applied (reload debounce) and the call was
// decided on the config before it; the next call was denied
// (rel-1-0-10:GAP-1699). A call that admission would let run now waits for a
// config write being applied and is refused by the block it adds, both for a
// request pinned to the earlier generation and for a server with no
// generations. A server the write does not block is still allowed with the
// pending warning, and with no write in flight nothing waits.
func TestGAP1699BlockWrittenWhileAdmissionPendingRefusesTheFirstCall(t *testing.T) {
	pending := func(_, server, _, _ string) watcher.MCPAdmissionStatus {
		return watcher.MCPAdmissionStatus{Name: server, Pending: true, RetryAfter: time.Minute}
	}
	t.Run("live config", func(t *testing.T) {
		var live atomic.Pointer[config.Config]
		live.Store(gap1699Config(false))
		api := &APIServer{scannerCfg: live.Load()}
		api.configSnapshot = live.Load
		api.SetMCPAdmissionStatus(pending)
		if resp := gap1699Call(api, context.Background(), "dcc1699"); resp.Action != "allow" || !resp.WouldBlock {
			t.Fatalf("control before the block: %+v, want the pending allow", resp)
		}
		gap1699Reload(t, 200*time.Millisecond, func() { live.Store(gap1699Config(true)) })
		if resp := gap1699Call(api, context.Background(), "dcc1699"); resp.Action != "block" {
			t.Fatalf("first call while the block is applied: action %q reason %q, want block", resp.Action, resp.Reason)
		}
	})
	t.Run("pinned generation", func(t *testing.T) {
		var live atomic.Pointer[Generation]
		before := gap1699Config(false)
		live.Store(&Generation{N: 1, Digest: "sha256:before", Config: before})
		api := &APIServer{scannerCfg: before}
		api.SetGenerationSource(live.Load)
		api.SetMCPAdmissionStatus(pending)
		pinned := withPinnedGeneration(context.Background(), live.Load())
		gap1699Reload(t, 200*time.Millisecond, func() {
			live.Store(&Generation{N: 2, Digest: "sha256:after", Config: gap1699Config(true)})
		})
		if resp := gap1699Call(api, pinned, "dcc1699"); resp.Action != "block" {
			t.Fatalf("first call pinned before the block: action %q reason %q, want block", resp.Action, resp.Reason)
		}
		// Another server stays on the pending allow.
		if resp := gap1699Call(api, pinned, "notes"); resp.Action != "allow" || !resp.WouldBlock {
			t.Fatalf("unblocked server: %+v, want the pending allow", resp)
		}
	})
	t.Run("no write in flight", func(t *testing.T) {
		api := &APIServer{scannerCfg: gap1699Config(false)}
		api.SetMCPAdmissionStatus(pending)
		start := time.Now()
		if resp := gap1699Call(api, context.Background(), "notes"); resp.Action != "allow" {
			t.Fatalf("pending server: %+v, want allow", resp)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("a call with no config write in flight waited %v", elapsed)
		}
	})
}
