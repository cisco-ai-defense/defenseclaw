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

import (
	"context"
	"net/http"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// disabledConnectorCallKey marks a hook-socket call the peer authorization
// let through only because the administrator's config turns its connector
// off (managedHookDecision.Disabled, rel-1-0-6:GAP-0325).
type disabledConnectorCallKey struct{}

func withDisabledConnectorCall(ctx context.Context) context.Context {
	return context.WithValue(ctx, disabledConnectorCallKey{}, true)
}

func disabledConnectorCall(ctx context.Context) bool {
	marked, _ := ctx.Value(disabledConnectorCallKey{}).(bool)
	return marked
}

// answerDisabledConnectorHook answers allow, and records nothing, for a call
// the hook socket let through as a disabled connector's: DefenseClaw does
// not inspect that agent, so its prompts and tool calls are not correlated,
// journaled, audited or exported, and no instruction snapshot is taken. It
// runs after the route's contract and malformed-payload checks. It reports
// false, and the call takes the ordinary path, when a refusal still applies
// (the require-sandbox host-run floor, the strict install window), for a
// sandbox or hook-side refusal report, and when the live configuration no
// longer disables the connector (a reload re-enabled it: the call is then
// inspected). The gateway log line written by the peer authorization is the
// only trace.
func (a *APIServer) answerDisabledConnectorHook(ctx context.Context, w http.ResponseWriter, header http.Header,
	profile connector.HookProfile, connectorName string, req agentHookRequest,
) bool {
	if !disabledConnectorCall(ctx) || hookSideRefusal(ctx) || isSandboxHookRequest(ctx) || sandboxHookForConnector(ctx, connectorName) {
		return false
	}
	if !a.hookEnablementConfig(ctx).ConnectorDisabled(connectorName) {
		return false
	}
	cwd := strings.TrimSpace(req.CWD)
	if cwd == "" {
		cwd = hookCWDForContext(ctx, req.CWD)
	}
	if a.requireSandboxDecision(ctx, connectorName, req.HookEventName, cwd, requireSandboxSurface(ctx, header)).refuses() {
		return false
	}
	if _, gated := a.strictInstallWindowGate(ctx, profile, connectorName, req); gated {
		return false
	}
	resp := agentHookResponseForProfile(profile, req, "allow", "allow", "NONE", "", nil,
		a.agentHookMode(ctx, connectorName), false, profile.Capabilities)
	writeHookAnswer(w, a.hookAnswerBody(ctx, profile, connectorName, req, resp, ""))
	return true
}
