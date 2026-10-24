// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// A profile decision that depends on an unproven identity fact or an
// uncompiled meet is refused on every blocking surface. Name remains
// diagnostic context for surfaces whose events cannot be blocked.

func profileRefusal(ctx context.Context) string {
	if resolved := resolvedGuardrailProfileFrom(ctx); resolved != nil {
		return resolved.decision.Refused
	}
	return ""
}

// profileRefused is why ctx's profile decision is Refused, or "".
func (a *APIServer) profileRefused(ctx context.Context) string {
	if resolved := a.resolvedProfile(ctx); resolved != nil {
		return resolved.decision.Refused
	}
	return ""
}

// refuseProfileHook answers a hook whose profile decision is Refused with a
// block, rendered for the agent. Whether a connector honours a block for
// that event is reported separately as WouldBlock.
func (a *APIServer) refuseProfileHook(
	ctx context.Context,
	profile connector.HookProfile,
	connectorName string,
	req agentHookRequest,
	rawBody []byte,
	payload map[string]interface{},
) (resp agentHookResponse, refused bool) {
	reason := a.profileRefused(ctx)
	if reason == "" {
		return agentHookResponse{}, false
	}
	_, wouldBlock := mapHookActionForProfile("block", "action", req.HookEventName, profile.Capabilities, profile, payload)
	resp = agentHookResponse{
		Action: "block", RawAction: "block", Severity: "HIGH", Mode: "action",
		WouldBlock: wouldBlock, Reason: reason,
	}
	refused = true
	defer func() {
		if recovered := recover(); recovered != nil {
			// resp stays the bare block.
			a.handleHookPanic(ctx, connectorName, req.HookEventName, fmt.Sprintf("profile refusal render panic: %v", recovered))
		}
	}()
	resp = a.renderSandboxVerdict(ctx, profile, req, rawBody, payload, resp, reason)
	return resp, refused
}

// refuseProfileInspect answers an inspect request whose profile decision is
// Refused with a block verdict, audited as action on route, and reports
// whether it did. Each inspect handler calls it, so a sandbox relay of the
// request, which does not pass the inspect middleware, is refused too.
func (a *APIServer) refuseProfileInspect(w http.ResponseWriter, r *http.Request, route, action, target string) bool {
	reason := a.profileRefused(r.Context())
	if reason == "" {
		return false
	}
	fmt.Fprintf(os.Stderr, "[inspect] REFUSED %s: guardrail profile decision\n", route)
	if a.logger != nil {
		_ = a.logger.LogEventCtx(r.Context(), a.inspectAuditEvent(r, route, action, target,
			"severity=HIGH mode=action reason=guardrail_profile_refused"))
	}
	a.writeJSON(w, http.StatusOK, &ToolInspectVerdict{
		Action: "block", RawAction: "block", Severity: "HIGH", Confidence: 1,
		Reason: reason, Findings: []string{}, Mode: "action",
	})
	return true
}

// refuseProfileProxy answers a proxied model request whose profile decision
// is Refused and reports whether it did.
func refuseProfileProxy(w http.ResponseWriter, r *http.Request) bool {
	reason := profileRefusal(r.Context())
	if reason == "" {
		return false
	}
	fmt.Fprintf(os.Stderr, "[guardrail] REFUSED %s: guardrail profile decision\n", r.URL.Path)
	writeOpenAIError(w, http.StatusForbidden, reason)
	return true
}
