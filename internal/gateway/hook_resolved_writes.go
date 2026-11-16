// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

type resolvedWritesContextKey struct{}

func resolvedWritesFromContext(ctx context.Context) map[string]string {
	targets, _ := ctx.Value(resolvedWritesContextKey{}).(map[string]string)
	return targets
}

// commandHookResolvedWrites is the client's write-target evidence for a
// Claude Code or Codex command-hook tool call. On a managed host outside
// Secure Client, both the native hook and the shell hooks resolve every
// shell call as the user and send the header. A shell call from a verified
// managed hook peer without it means the client resolver failed, so no
// operand is described: the evidence is incomplete, and a write the gateway
// cannot place itself fails closed (GAP-0280). In-agent plugin connectors
// send no header and never reach this path.
func commandHookResolvedWrites(ctx context.Context, cfg *config.Config, input actionfacts.Input) map[string]string {
	targets := resolvedWritesFromContext(ctx)
	if targets != nil || runtime.GOOS == "windows" || isSandboxHookRequest(ctx) ||
		cfg != nil && cfg.SecureClientIntegration() {
		return targets
	}
	if _, managed := managedHookPeerFromContext(ctx); !managed ||
		!trustedBashExecutionTool(input.Tool) || len(bytes.TrimSpace(input.Args)) == 0 {
		return targets
	}
	return map[string]string{hookpaths.TruncatedKey: "1"}
}
