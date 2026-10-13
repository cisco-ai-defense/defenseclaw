// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// hookSideRefusalKey marks a hook call that only reports a refusal the hook
// made itself (hookexec.HookRefusalHeader).
type hookSideRefusalKey struct{}

func withHookSideRefusal(ctx context.Context, header http.Header) context.Context {
	if strings.TrimSpace(header.Get(hookexec.HookRefusalHeader)) != hookexec.HookRefusalPayloadTooLarge {
		return ctx
	}
	return context.WithValue(ctx, hookSideRefusalKey{}, true)
}

func hookSideRefusal(ctx context.Context) bool {
	refused, _ := ctx.Value(hookSideRefusalKey{}).(bool)
	return refused
}

// hookPayloadTooLargeRuleID names the decision of a call a hook refused as
// too large to inspect: no rule pack rule matched it, so dashboards and
// searches find these refusals by this ID.
const hookPayloadTooLargeRuleID = "HOOK-PAYLOAD-TOO-LARGE"

// hookSideRefusalResponse is the decision recorded for a call a standalone
// hook refused as too large to inspect (GAP-0965, GAP-1042). The hook has
// already blocked the call; its report carries the event and session fields
// and no content, so nothing is evaluated. The audit row, the hook decision
// record and the block metrics name the connector, the user and the agent
// and session identities, as for every other block.
func (a *APIServer) hookSideRefusalResponse(ctx context.Context, connectorName string, req agentHookRequest) agentHookResponse {
	profile := a.hookProfileForRequest(ctx, connectorName)
	mode := sandboxHookMode(ctx, connectorName, a.agentHookMode(ctx, connectorName))
	reason := "DefenseClaw blocked this " + hookRefusalSubject(req.HookEventName) +
		": it is too large for DefenseClaw to inspect."
	resp := agentHookResponseForProfile(profile, req, "block", "block", "MEDIUM", reason, nil, mode, false, profile.Capabilities)
	resp.RuleIDs = []string{hookPayloadTooLargeRuleID}
	resp.SourceReason = reason
	return resp
}

// hookRefusalSubject names what a hook event carries: a prompt, a tool call
// or a tool result.
func hookRefusalSubject(event string) string {
	switch {
	case isPromptLikeEvent(event):
		return "prompt"
	case isGenericToolInspectionEvent(event):
		return "tool call"
	case isResultLikeEvent(event):
		return "tool result"
	}
	return "request"
}
