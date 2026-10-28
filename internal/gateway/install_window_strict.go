// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// hookInstallWindowStrictRuleID names the decision of a call the strict
// policy tier refused because an install or upgrade of this account's
// DefenseClaw holds its data directory.
const hookInstallWindowStrictRuleID = "HOOK-INSTALL-WINDOW-STRICT"

// strictInstallWindowReasonTail follows "DefenseClaw blocked this <subject>"
// in the reason of a hookInstallWindowStrictRuleID block. It names the
// install as the hooks' own install-window answer does.
const strictInstallWindowReasonTail = ": DefenseClaw is being installed or upgraded for this account, and the " +
	"strict policy tier lets no call run until that is done. Try again in a moment; if the installer has " +
	"stopped, run the installer again to finish or undo the interrupted install."

// strictInstallWindowReason is the reason of a hookInstallWindowStrictRuleID
// block of event.
func strictInstallWindowReason(event string) string {
	return "DefenseClaw blocked this " + hookRefusalSubject(event) + strictInstallWindowReasonTail
}

// trustedStrictInstallWindowReason reports whether reason is exactly a
// strictInstallWindowReason: gateway text only, nothing from the payload, so
// the agent is shown it as written.
func trustedStrictInstallWindowReason(reason string) bool {
	subject, ok := strings.CutPrefix(reason, "DefenseClaw blocked this ")
	if !ok {
		return false
	}
	subject, ok = strings.CutSuffix(subject, strictInstallWindowReasonTail)
	if !ok {
		return false
	}
	switch subject {
	case "prompt", "tool call", "tool result", "request":
		return true
	}
	return false
}

// perUserInstallWindowHeld reports a per-user gateway (not managed, not
// Secure Client) whose account's installer holds its data directory: the
// .install.lock install.sh and install.ps1 keep in the directory
// DEFENSECLAW_HOME names, or in this gateway's data_dir, read as the hooks
// read it (hookexec.InstallLockHeld: any file type, and a lock that cannot be
// read counts as held).
func (a *APIServer) perUserInstallWindowHeld() bool {
	if a == nil || a.scannerCfg == nil {
		return false
	}
	cfg := a.scannerCfg
	if managed.IsManagedEnterprise(cfg.DeploymentMode) || cfg.StandaloneEnterprise() || cfg.SecureClientIntegration() {
		return false
	}
	for _, dir := range []string{cfg.DataDir, config.DefaultDataPath()} {
		if strings.TrimSpace(dir) != "" && hookexec.InstallLockHeld(dir) {
			return true
		}
	}
	return false
}

// strictPolicyTierForHook reports whether connector's guardrail rule pack is
// the strict tier in the configuration that decides this request
// (decisionConfig: the profile the request resolves to, else the live base
// configuration), read as config.HookPolicyTierForConnector, the tier that
// also closes a per-user outage (config.HookOutageFailMode). A request whose
// profile gives the connector the default or permissive pack is not strict,
// whatever pack the base configuration names (loop round 2 review).
func (a *APIServer) strictPolicyTierForHook(ctx context.Context, connectorName string) bool {
	cfg := a.decisionConfig(ctx)
	return cfg != nil && cfg.HookPolicyTierForConnector(connectorName) == config.HookPolicyTierStrict
}

// installWindowStrict reports whether a per-user call of connectorName meets
// an install window (perUserInstallWindowHeld) in the strict tier. In the
// default and permissive tiers it logs one warning per install window and
// reports false: the gateway decides the call as at any other time. Sandbox
// calls are never gated here.
func (a *APIServer) installWindowStrict(ctx context.Context, connectorName string) bool {
	if !a.perUserInstallWindowHeld() {
		a.installWindowWarned.Store(false)
		return false
	}
	if sandboxHookForConnector(ctx, connectorName) {
		return false
	}
	if a.strictPolicyTierForHook(ctx, connectorName) {
		return true
	}
	if a.installWindowWarned.CompareAndSwap(false, true) {
		fmt.Fprintf(os.Stderr, "[gateway] warning: an install or upgrade of this account's DefenseClaw is "+
			"running; hook calls keep this gateway's answers until it is done (connector=%s, the strict "+
			"policy tier blocks them instead)\n", connectorName)
	}
	return false
}

// strictInstallWindowInspect is strictInstallWindowGate for the generic
// inspect route (the OpenClaw plugin's tool and prompt checks): in the
// strict tier a tool call or a prompt is blocked with the install reason.
// Only results the caller cannot refuse (tool results, completions and
// responses) are not gated. The OpenClaw plugin's message tool is checked
// from before_tool_call with direction "outbound", so it can still refuse
// the send: it is gated as a tool call (GAP-1452).
func (a *APIServer) strictInstallWindowInspect(ctx context.Context, connectorName string, req *ToolInspectRequest, verdict *ToolInspectVerdict) {
	if verdict == nil || req == nil {
		return
	}
	direction := strings.ToLower(strings.TrimSpace(req.Direction))
	switch direction {
	case "tool_result", "tool-response", "completion", "response":
		return
	}
	if !a.installWindowStrict(ctx, connectorName) {
		return
	}
	subject := "tool call"
	if strings.EqualFold(req.Tool, "message") && direction != "outbound" {
		subject = "prompt"
	}
	blockForStrictInstallWindow(verdict, subject)
}

// inspectRequestConnector is the connector an /api/v1/inspect/* request is
// decided for: the one it authenticated for, else this gateway's connector,
// as the tool route resolves it.
func inspectRequestConnector(ctx context.Context, configured string) string {
	if name := authenticatedInspectConnector(ctx); name != "" {
		return name
	}
	return canonicalConnectorRulePackKey(configured)
}

// strictInstallWindowInspectPrompt is strictInstallWindowInspect for the
// pre-request route (/api/v1/inspect/request), whose caller checks a prompt
// before it is sent and can refuse it.
func (a *APIServer) strictInstallWindowInspectPrompt(ctx context.Context, connectorName string, verdict *ToolInspectVerdict) {
	if verdict == nil || !a.installWindowStrict(ctx, connectorName) {
		return
	}
	blockForStrictInstallWindow(verdict, "prompt")
}

// blockForStrictInstallWindow makes verdict the strict install-window block
// of subject. The block stands in every guardrail mode, as on the hook
// route: the verdict is in action mode, because the OpenClaw plugin (and any
// inspect caller) enforces a block only in action mode, and an observe-mode
// strict gateway let the call run (loop round 1 review, GAP-1452 class).
func blockForStrictInstallWindow(verdict *ToolInspectVerdict, subject string) {
	verdict.Action, verdict.RawAction, verdict.Severity, verdict.Confidence = "block", "block", "HIGH", 1.0
	verdict.Mode = "action"
	verdict.WouldBlock = false
	verdict.Reason = "DefenseClaw blocked this " + subject + strictInstallWindowReasonTail
	verdict.Findings = append(verdict.Findings, hookInstallWindowStrictRuleID)
}

// strictInstallWindowGate answers a per-user call that reaches this gateway
// while an install or upgrade of the account holds its data directory (owner
// decision 2026-10-24, GAP-1372, GAP-1438). In the default and permissive
// tiers the gateway decides the call as at any other time, and it logs one
// warning per install window. In the strict tier every tool call and prompt
// the connector can refuse is blocked with the install reason, whatever the
// policy would answer and in every guardrail mode, as a strict outage is
// closed. Lifecycle and stop events, tool results, sandbox calls, managed
// and Secure Client gateways are never gated here. Because the gateway
// answers, every hook form (shell hooks, in-agent plugins, the native hook,
// and the hooks an upgrade from 1.0.2 or 1.0.3 has not rendered again yet)
// gets the same answer.
func (a *APIServer) strictInstallWindowGate(
	ctx context.Context,
	profile connector.HookProfile,
	connectorName string,
	req agentHookRequest,
) (agentHookResponse, bool) {
	if !a.installWindowStrict(ctx, connectorName) {
		return agentHookResponse{}, false
	}
	event := req.HookEventName
	if hookexec.LifecycleEvent(connectorName, event) || terminalLifecycleEvent(connectorName, event) ||
		isResultLikeEvent(event) {
		return agentHookResponse{}, false
	}
	if action, _ := mapHookActionForProfile("block", "action", event, profile.Capabilities, profile, req.Payload); action != "block" {
		return agentHookResponse{}, false
	}
	reason := strictInstallWindowReason(event)
	resp := agentHookResponseForProfile(profile, req, "block", "block", "HIGH", reason,
		[]string{hookInstallWindowStrictRuleID}, "action", false, profile.Capabilities)
	resp.RuleIDs = []string{hookInstallWindowStrictRuleID}
	resp.SourceReason = reason
	return resp, true
}
