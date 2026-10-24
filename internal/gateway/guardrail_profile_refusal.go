// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// A profile decision that depends on an unproven identity fact is refused,
// under strict, on the surfaces a candidate blocks (unprovenRefusal). Name
// remains the meet of possible profiles for diagnostics there, and applies
// in its own mode on every other surface.

// profileSurfaces are request surfaces a refused decision blocks
// (profileDecision.RefusedOn).
type profileSurfaces uint8

const (
	// profileSurfaceHooks are agent hook events, which the hook mode
	// decides.
	profileSurfaceHooks profileSurfaces = 1 << iota
	// profileSurfaceInspect are /api/v1/inspect and the LLM proxy, which
	// the inspect (guardrail) mode decides.
	profileSurfaceInspect
)

// profileSurfacesAll is every surface: ACP and sandboxes, which neither
// mode alone decides, are refused on a refusal of any surface.
const profileSurfacesAll = profileSurfaceHooks | profileSurfaceInspect

// names lists the surfaces for explain; none set is every surface.
func (s profileSurfaces) names() []string {
	if s == 0 {
		s = profileSurfacesAll
	}
	var out []string
	if s&profileSurfaceHooks != 0 {
		out = append(out, "hooks")
	}
	if s&profileSurfaceInspect != 0 {
		out = append(out, "inspect")
	}
	return out
}

// refusedOn is why d is refused on any of surfaces, or "". A refusal with
// no surfaces set covers every surface.
func (d profileDecision) refusedOn(surfaces profileSurfaces) string {
	if d.Refused == "" || d.RefusedOn != 0 && d.RefusedOn&surfaces == 0 {
		return ""
	}
	return d.Refused
}

// profileRefusal is why ctx's profile decision is refused on any of
// surfaces, or "".
func profileRefusal(ctx context.Context, surfaces profileSurfaces) string {
	if resolved := resolvedGuardrailProfileFrom(ctx); resolved != nil {
		return resolved.decision.refusedOn(surfaces)
	}
	return ""
}

// profileRefused is why ctx's profile decision is refused on any of
// surfaces, or "".
func (a *APIServer) profileRefused(ctx context.Context, surfaces profileSurfaces) string {
	if resolved := a.resolvedProfile(ctx); resolved != nil {
		return resolved.decision.refusedOn(surfaces)
	}
	return ""
}

// profileRefusedFor is profileRefused for a request whose mode is
// connectorName's, which need not be the connector its decision was taken
// for (profileRequestConnector): /api/v1/inspect/tool applies the mode of
// the gateway's own connector to a credential not scoped to one. An
// unproven decision is refused there only where a strict candidate blocks
// connectorName (decideUnproven), so a candidate's global strict action
// does not refuse a connector it sets to observe, and its strict action
// for that connector refuses it (review of r104 Q-identity, continuation 5,
// loop round 1).
func (a *APIServer) profileRefusedFor(ctx context.Context, surfaces profileSurfaces, connectorName string) string {
	resolved := a.resolvedProfile(ctx)
	if resolved == nil {
		return ""
	}
	d := resolved.decision
	if connectorName = config.NormalizeConnectorName(connectorName); resolved.set != nil && len(d.Unproven) > 0 && d.unprovenWhy != "" &&
		connectorName != config.NormalizeConnectorName(profileRequestConnector(ctx)) {
		resolved.set.decideUnproven(&d, connectorName)
	}
	return d.refusedOn(surfaces)
}

// refuseProfileHook answers a hook whose profile decision is refused on
// hooks with a block, rendered for the agent. Whether a connector honours a
// block for that event is reported separately as WouldBlock.
func (a *APIServer) refuseProfileHook(
	ctx context.Context,
	profile connector.HookProfile,
	connectorName string,
	req agentHookRequest,
	rawBody []byte,
	payload map[string]interface{},
) (resp agentHookResponse, refused bool) {
	reason := a.profileRefused(ctx, profileSurfaceHooks)
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
// refused on inspect with a block verdict, audited as action on route, and reports
// whether it did. Each inspect handler calls it, so a sandbox relay of the
// request, which does not pass the inspect middleware, is refused too.
func (a *APIServer) refuseProfileInspect(w http.ResponseWriter, r *http.Request, route, action, target string) bool {
	return a.refuseProfileInspectFor(w, r, route, action, target, profileRequestConnector(r.Context()))
}

// refuseProfileInspectFor is refuseProfileInspect for a handler that
// applies connectorName's inspect mode (profileRefusedFor).
func (a *APIServer) refuseProfileInspectFor(w http.ResponseWriter, r *http.Request, route, action, target, connectorName string) bool {
	reason := a.profileRefusedFor(r.Context(), profileSurfaceInspect, connectorName)
	if reason == "" {
		return false
	}
	fmt.Fprintf(os.Stderr, "[inspect] REFUSED %s: identity fact unproven\n", route)
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
// is refused on inspect and reports whether it did.
func refuseProfileProxy(w http.ResponseWriter, r *http.Request) bool {
	reason := profileRefusal(r.Context(), profileSurfaceInspect)
	if reason == "" {
		return false
	}
	fmt.Fprintf(os.Stderr, "[guardrail] REFUSED %s: identity fact unproven\n", r.URL.Path)
	writeOpenAIError(w, http.StatusForbidden, reason)
	return true
}
