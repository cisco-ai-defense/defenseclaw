// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// revealHeader is the HTTP header callers set to opt into receiving
// un-redacted finding evidence in the /inspect response body. Every
// request that sets this header is audit-logged with the caller's
// remote address so operators have a trail of who requested raw PII.
//
// Any value other than the exact string "1" is treated as not set;
// this keeps operator fat-fingers (e.g. "true", "yes") from silently
// flipping the switch — the header is an escape hatch, not a mode.
const revealHeader = "X-DefenseClaw-Reveal-PII"

// wantsReveal reports whether the caller has opted into raw PII in
// the HTTP response. Returning true causes the handler to:
//   - emit DetailedFindings with their original Evidence strings,
//   - emit verdict.Reason with the original matched literals,
//   - log an audit event tagged "inspect-reveal" so the choice is
//     discoverable by compliance review.
//
// Destination projection is unaffected: canonical telemetry keeps the source
// facts and the unified v8 router applies each destination's selected redaction
// profile independently. The response header changes only this HTTP response;
// it cannot make a configured destination more or less restrictive. An
// explicit managed-enterprise redact directive remains authoritative over the
// response header.
func wantsReveal(r *http.Request) bool {
	return r.Header.Get(revealHeader) == "1"
}

// ToolInspectRequest is the payload for POST /api/v1/inspect/tool.
// A single endpoint handles both general tool policy checks and message
// content inspection — the handler branches on the Tool field.
type ToolInspectRequest struct {
	Tool            string          `json:"tool"`
	Args            json.RawMessage `json:"args,omitempty"`
	Content         string          `json:"content,omitempty"`
	Direction       string          `json:"direction,omitempty"`
	SessionID       string          `json:"session_id,omitempty"`
	ApprovalSurface string          `json:"approval_surface,omitempty"`
	// Connector is an optional assertion. The authenticated server route
	// selects the connector generation; a mismatched assertion is rejected.
	Connector     string `json:"connector,omitempty"`
	MCPServerName string `json:"mcp_server_name,omitempty"`
	// contentScope is set only after a connector adapter derives content
	// provenance from its typed hook payload. It is deliberately not accepted
	// from the public inspect wire, where a caller could otherwise promote its
	// own content into the trust-exploit enforcement lane. The zero value keeps
	// the legacy public inspect API; native adapters opt in after establishing a
	// prompt or tool-result boundary.
	contentScope ruleContentScope
}

// ToolInspectVerdict is the response from the inspect endpoint.
//
// Observe-mode contract:
//
//   - Action is the value the hook script consumes. When the operator
//     has set guardrail.mode=observe (or the per-component mode is
//     not "action"), Action is downgraded to "allow" by applyMode()
//     so the hook script does not exit non-zero, mirroring the
//     evaluate{Codex,ClaudeCode}Hook handlers.
//   - RawAction preserves what the rule scanner would have decided
//     before the mode downgrade, so audit, OTel, and dashboards can
//     still see the latent verdict.
//   - WouldBlock=true means rawAction was "block" but mode≠"action"
//     suppressed the kill switch. Operators reading the response can
//     surface "we would have blocked this" without actually killing
//     the agent's request.
//
// This shape is deliberately the same observe-aware schema the codex
// and claude-code hook responses use so a future generic inspect
// hook script can read .raw_action / .would_block uniformly.
type ToolInspectVerdict struct {
	Action            string        `json:"action"`
	RawAction         string        `json:"raw_action,omitempty"`
	Severity          string        `json:"severity"`
	Confidence        float64       `json:"confidence"`
	Reason            string        `json:"reason"`
	Findings          []string      `json:"findings"`
	DetailedFindings  []RuleFinding `json:"detailed_findings,omitempty"`
	Mode              string        `json:"mode"`
	WouldBlock        bool          `json:"would_block,omitempty"`
	ApprovalTimeoutMS int           `json:"approval_timeout_ms,omitempty"`
	// RedactionEnabled carries the cloud-controlled per-inspection
	// redaction directive from the AID lane through the hook-side
	// merge so the evaluate* callers can stamp it onto the request
	// ctx / emitted events. Tri-state (nil/true/false); never
	// serialized on the hook response wire.
	RedactionEnabled *bool `json:"-"`
	// managedAIDFailOpenReason is an internal accounting marker. The generic
	// HTTP handler consumes it only after selecting an allow result, so
	// a timed-out request that the connector fails closed cannot be counted as
	// a fail-open allow decision. It is never serialized.
	managedAIDFailOpenReason string
}

// applyMode stamps the active guardrail mode onto the verdict and,
// when mode is anything other than "action" (typically "observe"),
// downgrades a "block", "confirm", or "alert" verdict to "allow" while preserving
// the original decision in RawAction and setting WouldBlock for
// "block" downgrades.
//
// The hook scripts at internal/gateway/connector/hooks/inspect-*.sh
// inspect the .action field and exit 2 when it is "block"; the codex
// and claude-code hook handlers already perform an equivalent
// downgrade. Without this helper, operators who configured
// guardrail.mode=observe were silently still being blocked because
// the OpenClaw inspect handlers (handleInspect{Tool,Request,Response,
// ToolResponse}) emitted action=block regardless of mode.
func (v *ToolInspectVerdict) applyMode(mode string) {
	mode = strings.TrimSpace(mode)
	if mode == "" {
		mode = "observe"
	}
	v.Mode = mode
	v.RawAction = v.Action
	if mode == "action" {
		return
	}
	switch v.Action {
	case "block":
		v.WouldBlock = true
		v.Action = "allow"
	case "confirm", "alert":
		v.Action = "allow"
	}
}

// clampPromptDirectionToolVerdict mirrors clampPromptDirectionVerdict for the
// tool-inspect verdict shape used by the connector hook handlers. Done before
// applyMode so the "would-block" telemetry in observe mode reflects the
// already-clamped policy (alert), not the pre-clamp (block/confirm). The
// pre-clamp action is preserved in the verdict's Reason for audit.
//
// CRITICAL severity is exempt from the demotion — see the matching rationale
// on clampPromptDirectionVerdict.
func clampPromptDirectionToolVerdict(verdict *ToolInspectVerdict, direction string) {
	if verdict == nil {
		return
	}
	if guardrailSeverityRank(verdict.Severity) >= severityCritical {
		return
	}
	clamped, demoted := clampPromptDirectionAction(direction, verdict.Action)
	if !demoted {
		return
	}
	original := strings.TrimSpace(verdict.Action)
	verdict.Action = clamped
	verdict.Reason = appendVerdictReason(verdict.Reason,
		fmt.Sprintf("policy-action=%s %s", original, promptSurfaceClampReason))
}

// hookAIDInspect runs the optional Cisco AI Defense lane on the
// hook-side surface (tool calls + tool results + UserPromptSubmit
// for hook-only connectors). Returns nil when the AID lane is off
// (no inspector wired, ScanHookSurface=false, or AID client returns
// nil for any reason — bad payload, transport failure, etc.).
//
// The proxy lane keeps owning chat prompts + completions for
// OpenClaw / ZeptoClaw, so this lane only fires on directions the
// proxy never sees: tool_call, tool_result, and the prompt
// direction emitted from UserPromptSubmit on hook-only connectors.
// Surface gating is intentional — without it, OpenClaw operators
// who set scanner_mode=remote AND configure cisco_ai_defense.api_key
// would double-scan chat traffic (proxy lane + hook lane).
// managedAIDOnly reports whether this hook lane is running under
// managed_enterprise, where Cisco AI Defense is the sole decision-maker
// and every local detector (static policy, regex, CodeGuard, judge) is
// bypassed. Boot- and reload-reliable: a.scannerCfg.DeploymentMode is
// the config the APIServer was constructed / reloaded with.
func (a *APIServer) managedAIDOnly() bool {
	return a != nil && a.scannerCfg != nil && managed.IsManagedEnterprise(a.scannerCfg.DeploymentMode)
}

// inspectManagedAIDOnly is the managed_enterprise hook-lane inspection
// path: Cisco AI Defense is the only thing that can block. Static
// block/allow lists, MCP-server blocks, connector regex packs, CodeGuard,
// and the LLM judge are all skipped. When AID returns no verdict (unwired /
// down / timeout / token failure — hookAIDInspect returns nil), the request
// fails open with an explicit allow verdict.
func (a *APIServer) inspectManagedAIDOnly(ctx context.Context, toolName, content string) *ToolInspectVerdict {
	failOpenReason := aidFailOpenUnavailable
	if !managedAIDHookContentIsInspectable(toolName, content) {
		failOpenReason = aidFailOpenNoContent
	} else if a == nil || a.ciscoInspector == nil || a.scannerCfg == nil ||
		!a.scannerCfg.CiscoAIDefense.HookSurfaceEnabled() {
		failOpenReason = aidFailOpenUnwired
	}
	aid := a.hookAIDInspect(ctx, toolName, content)
	if aid == nil {
		verdict := &ToolInspectVerdict{
			Action:                   "allow",
			Severity:                 "NONE",
			Findings:                 []string{},
			managedAIDFailOpenReason: failOpenReason,
		}
		if gate := managedAIDFailOpenNativeHookGateFromContext(ctx); gate != nil {
			gate.enqueue(verdict)
		} else if !managedAIDFailOpenAccountingDeferred(ctx) {
			a.recordManagedAIDFailOpenVerdict(ctx, verdict)
		}
		return verdict
	}
	return mergeWithAIDVerdict(nil, aid)
}

type managedAIDFailOpenAccountingContextKey struct{}

type managedAIDFailOpenNativeHookGateContextKey struct{}

// managedAIDFailOpenNativeHookGate holds fail-open candidates until the
// unified native-hook owner has selected the final effective response. Native
// evaluation can inspect more than one segment, so the gate preserves proposal
// order and consumes the whole batch exactly once.
type managedAIDFailOpenNativeHookGate struct {
	mu       sync.Mutex
	pending  []*ToolInspectVerdict
	consumed bool
}

func deferManagedAIDFailOpenAccounting(ctx context.Context) context.Context {
	return context.WithValue(ctx, managedAIDFailOpenAccountingContextKey{}, true)
}

func deferManagedAIDFailOpenNativeHookAccounting(
	ctx context.Context,
) (context.Context, *managedAIDFailOpenNativeHookGate) {
	gate := &managedAIDFailOpenNativeHookGate{}
	ctx = deferManagedAIDFailOpenAccounting(ctx)
	return context.WithValue(ctx, managedAIDFailOpenNativeHookGateContextKey{}, gate), gate
}

func managedAIDFailOpenNativeHookGateFromContext(
	ctx context.Context,
) *managedAIDFailOpenNativeHookGate {
	if ctx == nil {
		return nil
	}
	gate, _ := ctx.Value(managedAIDFailOpenNativeHookGateContextKey{}).(*managedAIDFailOpenNativeHookGate)
	return gate
}

func (gate *managedAIDFailOpenNativeHookGate) enqueue(verdict *ToolInspectVerdict) {
	if gate == nil || verdict == nil || verdict.managedAIDFailOpenReason == "" {
		return
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if gate.consumed {
		verdict.managedAIDFailOpenReason = ""
		return
	}
	gate.pending = append(gate.pending, verdict)
}

func (gate *managedAIDFailOpenNativeHookGate) consume(selectedAllow bool) []*ToolInspectVerdict {
	if gate == nil {
		return nil
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if gate.consumed {
		return nil
	}
	gate.consumed = true
	pending := gate.pending
	gate.pending = nil
	if selectedAllow {
		return pending
	}
	for _, verdict := range pending {
		if verdict != nil {
			verdict.managedAIDFailOpenReason = ""
		}
	}
	return nil
}

func managedAIDFailOpenAccountingDeferred(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	deferred, _ := ctx.Value(managedAIDFailOpenAccountingContextKey{}).(bool)
	return deferred
}

func (a *APIServer) recordManagedAIDFailOpenVerdict(ctx context.Context, verdict *ToolInspectVerdict) {
	if a == nil || verdict == nil || verdict.managedAIDFailOpenReason == "" {
		return
	}
	reason := verdict.managedAIDFailOpenReason
	verdict.managedAIDFailOpenReason = ""
	metricRuntime, _ := a.observabilityV8LifecycleRuntime().(hookLifecycleMetricV8Runtime)
	if metricRuntime != nil {
		_ = recordManagedAIDFailOpenMetricV8(ctx, metricRuntime, reason)
	}
}

func (a *APIServer) recordManagedAIDFailOpenForSelectedNativeHookResult(
	ctx context.Context,
	gate *managedAIDFailOpenNativeHookGate,
	action string,
	panicked bool,
) {
	pending := gate.consume(!panicked && action == "allow")
	if len(pending) == 0 {
		return
	}
	metricCtx, cancelMetric := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancelMetric()
	for _, verdict := range pending {
		a.recordManagedAIDFailOpenVerdict(metricCtx, verdict)
	}
}

func (a *APIServer) hookAIDInspect(ctx context.Context, toolName string, content string) *ScanVerdict {
	if a == nil || a.ciscoInspector == nil {
		return nil
	}
	if a.scannerCfg == nil || !a.scannerCfg.CiscoAIDefense.HookSurfaceEnabled() {
		return nil
	}
	if !managedAIDHookContentIsInspectable(toolName, content) {
		return nil
	}
	// Prepend the tool name to the content so AID classifiers that
	// match on tool-name strings (e.g. "Limit JIRA actions" /
	// "createJiraIssue") have it visible. AID's /inspect/chat reads
	// content as a free-text user message; the structured tool name
	// would otherwise be lost on the wire.
	body := content
	if toolName != "" && toolName != "message" {
		body = fmt.Sprintf("Tool call: %s\n%s", toolName, content)
	}
	return a.ciscoInspector.Inspect(ctx, []ChatMessage{{Role: "user", Content: body}})
}

// managedAIDHookContentIsInspectable applies text trimming only to the
// message hook, whose Content is sent to AID verbatim. Named tool calls keep
// their established exact-empty check: non-empty argument whitespace is
// still combined with the tool name below and remains policy-inspectable.
func managedAIDHookContentIsInspectable(toolName, content string) bool {
	if toolName == "message" {
		return managedAIDContentIsInspectable(content)
	}
	return content != ""
}

// mergeWithAIDVerdict folds an AID ScanVerdict into an existing
// ToolInspectVerdict using strictest-wins semantics: action escalates
// (allow → alert → block), severity escalates, findings concatenate.
// Used by the hook-lane callers below.
func mergeWithAIDVerdict(local *ToolInspectVerdict, aid *ScanVerdict) *ToolInspectVerdict {
	return mergeWithLaneVerdict(local, aid, "ai-defense:")
}

// mergeWithJudgeVerdict folds an LLM-judge ScanVerdict into the hook
// verdict with the same strictest-wins semantics as the AID lane.
// Findings are tagged "llm-judge:" so audit consumers can tell the
// lanes apart.
func mergeWithJudgeVerdict(local *ToolInspectVerdict, v *ScanVerdict) *ToolInspectVerdict {
	return mergeWithLaneVerdict(local, v, "llm-judge:")
}

// mergeWithLaneVerdict is the shared strictest-wins fold for the
// hook-side scan lanes (Cisco AID, LLM judge): action escalates
// (allow → alert → confirm → block), severity escalates, findings
// concatenate with the lane's tag prefix.
func mergeWithLaneVerdict(local *ToolInspectVerdict, aid *ScanVerdict, findingTag string) *ToolInspectVerdict {
	if aid == nil {
		return local
	}
	rank := func(action string) int {
		switch strings.ToLower(action) {
		case "block":
			return 3
		case "confirm", "ask":
			return 2
		case "alert":
			return 1
		default:
			return 0
		}
	}
	sevRank := func(s string) int {
		switch strings.ToUpper(s) {
		case "CRITICAL":
			return 4
		case "HIGH":
			return 3
		case "MEDIUM":
			return 2
		case "LOW":
			return 1
		default:
			return 0
		}
	}
	if local == nil {
		local = &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	}
	// AID-only escalation path: escalate the action when AID is
	// stricter, escalate the severity when AID is stricter, append
	// findings + reason so the audit trail shows both lanes.
	if rank(aid.Action) > rank(local.Action) {
		local.Action = aid.Action
	}
	if sevRank(aid.Severity) > sevRank(local.Severity) {
		local.Severity = aid.Severity
	}
	if len(aid.Findings) > 0 {
		// Tag lane findings so operators can tell them apart from
		// regex / CodeGuard hits when reading the audit log.
		for _, f := range aid.Findings {
			local.Findings = append(local.Findings, findingTag+f)
		}
		// Synthesize structured DetailedFindings from each lane finding so
		// the downstream emission pipeline (emitInspectVerdictFindings →
		// scanner.EmitInspectFindings → EmitScanResult) writes a
		// scan_results row and per-finding scan_findings rows. Without
		// this, the AID / LLM-judge lanes only populated the stringy
		// Findings slice, emitInspectVerdictFindings early-returned on
		// empty DetailedFindings, and managed_enterprise deployments
		// (where AID is the sole detector) never advanced total_scans on
		// the IPC stats surface even though every hook call ran an
		// inspection. Severity comes from the lane verdict; RuleID uses
		// the raw finding name so SIEM pivots by rule_id work identically
		// across the AID / judge / regex lanes. Confidence stays at 0
		// (lane doesn't self-report one); the emitter treats zero as
		// "not computed" and omits it on the wire.
		for _, f := range aid.Findings {
			rf := RuleFinding{
				RuleID:   f,
				Title:    f,
				Severity: aid.Severity,
				Tags:     []string{strings.TrimSuffix(findingTag, ":")},
			}
			local.DetailedFindings = append(local.DetailedFindings, rf)
		}
	}
	if aid.Reason != "" {
		if local.Reason != "" {
			local.Reason = local.Reason + "; " + aid.Reason
		} else {
			local.Reason = aid.Reason
		}
	}
	// Carry the cloud redaction directive through the merge. Guarded
	// by non-nil so only the AID lane (which alone populates it)
	// stamps it; the shared judge lane leaves it untouched.
	if aid.RedactionEnabled != nil {
		local.RedactionEnabled = aid.RedactionEnabled
	}
	return local
}

// inspectToolPolicy runs all rule categories against the tool args.
// No tool-name gating — every pattern fires on every tool.
//
// This is the no-context entry point used by the native hook handlers
// (codex / claude-code / agent). The optional judge lane (J3-3b) runs
// under a deadline-free context.Background() so it is bounded only by
// its own HookTimeout, never the 200ms rule-scan cap; see
// inspectToolPolicyCtx for the variant the generic /inspect/tool
// endpoint uses to short-circuit the judge under its 200ms deadline.
func (a *APIServer) inspectToolPolicy(req *ToolInspectRequest) *ToolInspectVerdict {
	return a.inspectToolPolicyCtx(context.Background(), req)
}

// inspectToolPolicyCtx is inspectToolPolicy with an explicit context for
// the judge lane's deadline guard. The generic /inspect/tool endpoint
// (handleInspectTool) passes its 200ms-capped ctx so the judge
// short-circuits there exactly as the message lane does; native hook
// callers reach this through inspectToolPolicy with context.Background().
func (a *APIServer) inspectToolPolicyCtx(ctx context.Context, req *ToolInspectRequest) *ToolInspectVerdict {
	action := trustedActionRequest{
		Input: actionfacts.Input{
			Tool: req.Tool,
			Args: req.Args,
		},
		LegacyText:         string(req.Args),
		Connector:          req.Connector,
		EnforcementCapable: true,
	}
	if argv, ok := parseTrustedShimArgv(req.Tool, req.Args); ok {
		action.Input = actionfacts.Input{
			Tool:       req.Tool,
			Argv:       argv,
			ActiveHome: trustedSameHostHome(),
		}
		action.LegacyText = serializeArgvForLegacyScan(argv)
	}
	return a.inspectTrustedToolPolicyCtx(ctx, req, action)
}

// parseTrustedShimArgv recognizes the exact argument envelope emitted by the
// authenticated PATH shims. A malformed, extended, or mismatched envelope is
// deliberately rejected so inspectToolPolicyCtx keeps its non-authoritative
// Args projection and owner-local regex fallback.
func parseTrustedShimArgv(tool string, raw json.RawMessage) ([]string, bool) {
	switch tool {
	case "curl", "wget", "ssh", "nc", "pip", "npm":
	default:
		return nil, false
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, false
	}

	var argv []string
	seenArgv := false
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil || key != "argv" || seenArgv {
			return nil, false
		}
		if err := decoder.Decode(&argv); err != nil {
			return nil, false
		}
		seenArgv = true
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return nil, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, false
	}
	if !seenArgv || len(argv) == 0 || argv[0] != tool {
		return nil, false
	}
	return argv, true
}

func (a *APIServer) inspectTrustedToolPolicyCtx(
	ctx context.Context,
	req *ToolInspectRequest,
	action trustedActionRequest,
) *ToolInspectVerdict {
	// managed_enterprise: Cisco AI Defense is the sole decision-maker.
	// Skip static block/allow + MCP-server block, connector regex packs,
	// CodeGuard, and the judge lane; AID inspects the tool call directly
	// and a nil AID verdict fails open. See inspectManagedAIDOnly.
	if a.managedAIDOnly() {
		return a.inspectManagedAIDOnly(ctx, req.Tool, string(req.Args))
	}

	// Static block/allow list takes priority — checked before any rule
	// scanning. Connector-scoped (@C/T) entries resolve before the bare
	// global entry, mirroring the sidecar lane and the PolicyEngine helpers:
	//   block @C/T → allow @C/T → block T → allow T → scan
	if a.store != nil {
		pe := enforce.NewPolicyEngine(a.store)
		// MCP-server runtime block: a blocked MCP server denies ALL of its
		// tools, regardless of any per-tool allow. This is the Go-side runtime
		// enforcement of `defenseclaw mcp block <server>` (global or
		// --connector scoped); it is checked before the per-tool block/allow so
		// a server-level block wins over a tool-level allow, and it fails closed
		// + loud on a store lookup error.
		if deny, _, reason := mcpServerRuntimeBlock(pe, req.Tool, req.Connector, req.MCPServerName); deny {
			return &ToolInspectVerdict{
				Action:     "block",
				Severity:   "HIGH",
				Confidence: 1.0,
				Reason:     reason,
				Findings:   []string{"MCP-BLOCK"},
			}
		}
		blocked, err := pe.IsToolBlockedForConnector(req.Tool, req.Connector)
		if err != nil {
			return toolPolicyLookupErrorVerdict("inspect", "block-list", req.Tool, req.Connector, err)
		}
		if blocked {
			return &ToolInspectVerdict{
				Action:     "block",
				Severity:   "HIGH",
				Confidence: 1.0,
				Reason:     fmt.Sprintf("tool %q is on the static block list", req.Tool),
				Findings:   []string{"STATIC-BLOCK"},
			}
		}
		// An explicit allow skips rule/pattern/AID/judge scanning. Write tools
		// still run CodeGuard on their content (D2): the allow bypasses the
		// scan gate, not code-content inspection.
		allowed, err := pe.IsToolAllowedForConnector(req.Tool, req.Connector)
		if err != nil {
			return toolPolicyLookupErrorVerdict("inspect", "allow-list", req.Tool, req.Connector, err)
		}
		if allowed {
			if !isWriteToolName(strings.ToLower(req.Tool)) {
				return &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{"STATIC-ALLOW"}}
			}
			if cg := a.runCodeGuardOnArgsWithProvenance(req); len(cg.findings) > 0 {
				return a.codeGuardOnlyVerdict(req, cg, true, action.EnforcementCapable)
			}
			return &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{"STATIC-ALLOW"}}
		}
	}

	argsStr := string(req.Args)
	toolName := req.Tool

	// The calling adapter established this as a trusted action. Structured
	// semantic evaluation and owner-local fallback share one immutable
	// connector generation.
	priorTelemetryRecorder := action.recordTelemetry
	action.recordTelemetry = func(observation trustedActionTelemetry) {
		if priorTelemetryRecorder != nil {
			priorTelemetryRecorder(observation)
		}
		a.recordParserUncertaintyMetricV8(
			ctx,
			firstNonEmpty(req.Connector, action.Connector),
			observation.ParserUncertaintyCount,
		)
	}
	ruleFindings := dispatchTrustedAction(ctx, action)

	// CodeGuard: scan file content for any file-write tool.
	//
	// the legacy gate matched only the canonical
	// `write_file` / `edit_file` names, but native connector events
	// emit aliases like Claude Code "Write" / "Edit" / "MultiEdit",
	// Codex "patch", and Cursor "applyDiff". Those bypassed CodeGuard
	// entirely while carrying the same code payload. We accept any
	// recognised file-write alias (case-insensitive).
	tool := strings.ToLower(toolName)
	isWriteTool := isWriteToolName(tool)
	var cgScan codeGuardArgsScan
	if isWriteTool {
		cgScan = a.runCodeGuardOnArgsWithProvenance(req)
	}
	cgFindings := codeGuardRuleFindings(cgScan, true, action.EnforcementCapable)

	var verdict *ToolInspectVerdict
	if len(ruleFindings) == 0 && len(cgFindings) == 0 {
		verdict = &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
		// Regex + CodeGuard found nothing locally. Give the AID lane a
		// turn — operators with custom AID policies (e.g. block
		// `createJiraIssue`, throttle `addComment`) want their rules to
		// fire even when no DefenseClaw built-in pattern matched.
		if aid := a.hookAIDInspect(ctx, toolName, argsStr); aid != nil && aid.Action != "allow" && aid.Action != "" {
			verdict = mergeWithAIDVerdict(nil, aid)
		}
	} else {
		severity := HighestSeverity(ruleFindings)
		enforceableSeverity := HighestSeverity(enforceableRuleFindings(ruleFindings))
		severity, enforceableSeverity = aggregateCodeGuardSeverity(
			cgFindings,
			severity,
			enforceableSeverity,
		)
		confidence := highestInspectConfidence(ruleFindings, cgFindings, severity)

		runtimeAction := guardrailActionAllow
		if enforceableSeverity != "NONE" {
			runtimeAction = guardrailRuntimeActionForConnector(
				a.scannerCfg,
				req.Connector,
				enforceableSeverity,
				true,
			)
		}

		reasons := make([]string, 0, minInt(len(ruleFindings), 5))
		for i, f := range ruleFindings {
			if i >= 5 {
				break
			}
			reasons = append(reasons, f.RuleID+":"+f.Title)
		}

		findingStrs := FindingStrings(ruleFindings)
		for _, cf := range cgFindings {
			findingStrs = append(findingStrs, fmt.Sprintf("codeguard:%s:%s", cf.RuleID, cf.Title))
		}

		verdict = &ToolInspectVerdict{
			Action:           runtimeAction,
			Severity:         severity,
			Confidence:       confidence,
			Reason:           fmt.Sprintf("matched: %s", strings.Join(reasons, ", ")),
			Findings:         findingStrs,
			DetailedFindings: append(ruleFindings, cgFindings...),
		}

		// AID lane: also forward to Cisco AI Defense when the operator has
		// configured a key. Strictest verdict wins via mergeWithAIDVerdict.
		// We send the rule reasons text rather than just the args because
		// AID's classifier reads free-text content; the rule names give it
		// useful context. The lane is silent when no AID client is wired
		// or when ScanHookSurface=false.
		if aid := a.hookAIDInspect(ctx, toolName, argsStr); aid != nil {
			verdict = mergeWithAIDVerdict(verdict, aid)
		}
	}

	// Judge lane (J3-3b): forward the tool args to the LLM judge for
	// connectors opted into the tool_call direction via
	// guardrail.judge.hook_connectors + EffectiveStrategy("tool_call").
	// Tool-call args are agent-initiated input, so they are judged under
	// the "prompt" direction (injection + exfil). The shipped default
	// (regex_only) returns nil and no LLM round-trip happens. Runs after
	// the regex/AID lanes so regex_judge can skip the round-trip when the
	// local lanes already condemned the call.
	if jv := a.runHookJudge(ctx, "tool_call", "prompt", req.Connector, argsStr, toolName, verdict); jv != nil {
		verdict = mergeWithJudgeVerdict(verdict, jv)
	}
	return verdict
}

// highestInspectConfidence keeps verdict confidence aligned with the visible
// finding that established the final severity, regardless of whether that
// finding came from the rule scanner or CodeGuard.
func highestInspectConfidence(ruleFindings, codeGuardFindings []RuleFinding, severity string) float64 {
	confidence := HighestConfidence(ruleFindings, severity)
	if codeGuardConfidence := HighestConfidence(codeGuardFindings, severity); codeGuardConfidence > confidence {
		confidence = codeGuardConfidence
	}
	return confidence
}

// unmarshalArgsObject decodes a tool-call args payload that may
// arrive either as a JSON object directly OR as a JSON string whose
// content is the object. the managed inspect-tool
// hook builds the request body with `jq --arg args "$TOOL_INPUT"`,
// so well-formed tool input becomes a string field. Returns ok=false
// when neither form yields a non-nil object.
func unmarshalArgsObject(raw json.RawMessage) (map[string]interface{}, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	var asObj map[string]interface{}
	if err := json.Unmarshal(raw, &asObj); err == nil && asObj != nil {
		return asObj, true
	}
	var asStr string
	if err := json.Unmarshal(raw, &asStr); err == nil && asStr != "" {
		var inner map[string]interface{}
		if err := json.Unmarshal([]byte(asStr), &inner); err == nil && inner != nil {
			return inner, true
		}
	}
	return nil, false
}

// isWriteToolName reports whether the lowercased tool name should
// trigger CodeGuard inspection. includes native
// connector aliases that previously bypassed CodeGuard (Write/Edit/
// MultiEdit/applyDiff/apply_patch/NotebookEdit/patch).
func isWriteToolName(tool string) bool {
	switch tool {
	case "write_file", "edit_file",
		"write", "edit", "multiedit", "multi_edit",
		"applydiff", "apply_diff", "applypatch", "apply_patch",
		"notebookedit", "notebook_edit", "patch",
		"create_file", "createfile", "fs_write", "fs_edit":
		return true
	}
	return false
}

// runCodeGuardOnArgs extracts path/content from write_file/edit_file args
// and runs CodeGuard content scanning.
func (a *APIServer) runCodeGuardOnArgs(req *ToolInspectRequest) []scanner.Finding {
	return a.runCodeGuardOnArgsWithProvenance(req).findings
}

type codeGuardArgsScan struct {
	findings []scanner.Finding
	complete bool
}

func (a *APIServer) runCodeGuardOnArgsWithProvenance(req *ToolInspectRequest) codeGuardArgsScan {
	// managed_enterprise: local content scanners (CodeGuard/ClawShield)
	// are disabled — AID is authoritative. Defense-in-depth: short-circuit
	// here too so no other caller re-introduces CodeGuard blocking in
	// managed mode (e.g. the allow-listed write-tool path).
	if a.managedAIDOnly() {
		return codeGuardArgsScan{}
	}
	// the managed inspect-tool hook serializes
	// TOOL_INPUT with `jq -n --arg args "$TOOL_INPUT"`, which yields
	// {"args": "<json-string>"} where `args` is a JSON STRING that
	// itself contains the object. The legacy code unmarshalled
	// req.Args directly into map[string]interface{} and bailed on
	// any error, so the hook path silently skipped CodeGuard. We
	// first try the object form; on failure we attempt to interpret
	// req.Args as a JSON string and unmarshal its contents.
	parsed, structurallyComplete := decodeCodeGuardArgsObject(req.Args)
	if parsed == nil {
		return codeGuardArgsScan{}
	}
	bestEffort := codeGuardBestEffortObject(parsed)

	filePath, pathComplete := exactCodeGuardStringField(parsed, bestEffort, "path", "file_path", "filePath")
	content, contentComplete := exactCodeGuardStringField(parsed, bestEffort, "content", "new_string", "text", "body")
	if filePath == "" || content == "" {
		return codeGuardArgsScan{}
	}

	if !scanner.IsCodeFile(filepath.Ext(filePath)) {
		return codeGuardArgsScan{}
	}

	rulesDir := ""
	if a.scannerCfg != nil {
		rulesDir = a.scannerCfg.Scanners.CodeGuard
	}
	cg := scanner.NewCodeGuardScanner(rulesDir)
	scan := cg.ScanContentWithProvenance(filePath, content)
	return codeGuardArgsScan{
		findings: scan.Findings(),
		complete: structurallyComplete && pathComplete && contentComplete && scan.Complete(),
	}
}

// decodeCodeGuardArgsObject preserves every field occurrence so proof-relevant
// aliases can be checked for ambiguity. Duplicate unrelated metadata is not a
// reason to discard otherwise exact path/content proof.
func decodeCodeGuardArgsObject(raw json.RawMessage) (map[string][]json.RawMessage, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err == nil {
		raw = json.RawMessage(encoded)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, false
	}
	fields := make(map[string][]json.RawMessage)
	complete := true
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, false
		}
		name, ok := key.(string)
		if !ok {
			return nil, false
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, false
		}
		fields[name] = append(fields[name], append(json.RawMessage(nil), value...))
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return nil, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		complete = false
	}
	return fields, complete
}

func codeGuardBestEffortObject(fields map[string][]json.RawMessage) map[string]interface{} {
	result := make(map[string]interface{}, len(fields))
	for name, values := range fields {
		if len(values) == 0 {
			continue
		}
		var value interface{}
		if err := json.Unmarshal(values[len(values)-1], &value); err == nil {
			result[name] = value
		}
	}
	return result
}

func exactCodeGuardStringField(
	raw map[string][]json.RawMessage,
	bestEffort map[string]interface{},
	names ...string,
) (string, bool) {
	present := 0
	value := ""
	exact := ""
	complete := true
	for _, name := range names {
		if candidate, ok := bestEffort[name].(string); ok && candidate != "" {
			value = candidate
			break
		}
	}
	for _, name := range names {
		values := raw[name]
		if len(values) == 0 {
			continue
		}
		present += len(values)
		for _, encoded := range values {
			var candidate string
			if err := json.Unmarshal(encoded, &candidate); err != nil || candidate == "" {
				complete = false
				continue
			}
			if exact == "" {
				exact = candidate
			} else if candidate != exact {
				complete = false
			}
		}
	}
	return value, complete && present > 0 && value != "" && value == exact
}

// CodeGuard reports exact binary matches rather than probabilistic scores. Its
// scanner findings intentionally leave confidence unset; the gateway projection
// makes that binary certainty explicit without changing enforcement provenance.
const codeGuardBinaryConfidence = 1.0

// codeGuardOnlyVerdict builds a verdict from CodeGuard findings alone, for an
// allow-listed WRITE tool whose content CodeGuard flagged. The allow skipped
// rule/AID/judge scanning, but CodeGuard is retained (D2); severity and action
// mirror the main inspectToolPolicy path with no rule findings.
func (a *APIServer) codeGuardOnlyVerdict(
	req *ToolInspectRequest,
	scan codeGuardArgsScan,
	trustedBoundary bool,
	enforcementCapable bool,
) *ToolInspectVerdict {
	cgFindings := codeGuardRuleFindings(scan, trustedBoundary, enforcementCapable)
	severity, enforceableSeverity := aggregateCodeGuardSeverity(
		cgFindings,
		"NONE",
		"NONE",
	)
	action := guardrailActionAllow
	if enforceableSeverity != "NONE" {
		action = guardrailRuntimeActionForConnector(a.scannerCfg, req.Connector, enforceableSeverity, true)
	}
	findingStrs := make([]string, 0, len(cgFindings))
	for _, cf := range cgFindings {
		findingStrs = append(findingStrs, fmt.Sprintf("codeguard:%s:%s", cf.RuleID, cf.Title))
	}
	confidence := 0.0
	if len(cgFindings) > 0 {
		confidence = codeGuardBinaryConfidence
	}
	return &ToolInspectVerdict{
		Action:           action,
		Severity:         severity,
		Confidence:       confidence,
		Reason:           fmt.Sprintf("allow-listed tool %q: CodeGuard retained on write", req.Tool),
		Findings:         findingStrs,
		DetailedFindings: cgFindings,
	}
}

// aggregateCodeGuardSeverity folds visible and enforcement-eligible CodeGuard
// findings independently. A detection-only CRITICAL finding remains visible at
// CRITICAL without hiding a lower-severity finding that can actually enforce.
func aggregateCodeGuardSeverity(
	findings []RuleFinding,
	severity string,
	enforceableSeverity string,
) (string, string) {
	for _, finding := range findings {
		findingSeverity := strings.ToUpper(strings.TrimSpace(finding.Severity))
		if severityRank[findingSeverity] > severityRank[severity] {
			severity = findingSeverity
		}
		if finding.contributesToEnforcement() &&
			severityRank[findingSeverity] > severityRank[enforceableSeverity] {
			enforceableSeverity = findingSeverity
		}
	}
	return severity, enforceableSeverity
}

func codeGuardRuleFindings(
	scan codeGuardArgsScan,
	trustedBoundary bool,
	enforcementCapable bool,
) []RuleFinding {
	if len(scan.findings) == 0 {
		return nil
	}
	result := make([]RuleFinding, 0, len(scan.findings))
	for _, finding := range scan.findings {
		ruleID := firstNonEmpty(finding.RuleID, finding.ID)
		if ruleID == "" {
			continue
		}
		title := strings.TrimSpace(finding.Title)
		builtinMatch := finding.CodeGuardBuiltinMatch(ruleID)
		if title == "" {
			title = ruleID
			builtinMatch = false
		}
		converted := RuleFinding{
			RuleID: ruleID, Title: title, Severity: string(finding.Severity),
			Confidence: codeGuardBinaryConfidence, Tags: append([]string(nil), finding.Tags...),
			ToolCapabilityClass: finding.ToolCapabilityClass,
		}.withTrustedActionProof(newExactCodeGuardFindingProof(
			ruleID,
			trustedBoundary,
			scan.complete,
			builtinMatch,
		))
		result = append(result, converted)
	}
	return applyTrustedActionProofBoundary(result, enforcementCapable)
}

// inspectMessageContent scans outbound message content for secrets, PII,
// and data exfiltration patterns. Uses the same rule engine.
func (a *APIServer) inspectMessageContent(ctx context.Context, req *ToolInspectRequest) *ToolInspectVerdict {
	content := req.Content
	if content == "" {
		var parsed map[string]interface{}
		if err := json.Unmarshal(req.Args, &parsed); err == nil {
			if c, ok := parsed["content"].(string); ok {
				content = c
			} else if c, ok := parsed["body"].(string); ok {
				content = c
			}
		}
	}

	// managed_enterprise: Cisco AI Defense is the sole decision-maker.
	// Skip the connector regex packs and the judge lane; AID inspects the
	// message content directly and a nil AID verdict fails open.
	if a.managedAIDOnly() {
		verdict := a.inspectManagedAIDOnly(ctx, "message", content)
		if req.contentScope == ruleContentScopeSource {
			clampSourceScopeVerdict(verdict)
		}
		return verdict
	}

	if content == "" {
		return &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	}

	// Outbound messages get the full scan — tool name "message" for context.
	// Routed through the request's connector so each connector scans against
	// its own rule pack (empty ⇒ process-global default set).
	var ruleFindings []RuleFinding
	if req.contentScope != ruleContentScopeAll {
		ruleFindings = scanContentRulesForConnector(
			req.Connector,
			content,
			"message",
			req.contentScope,
		)
	} else {
		ruleFindings = ScanAllRulesForConnector(req.Connector, content, "message")
	}

	var verdict *ToolInspectVerdict
	if len(ruleFindings) == 0 {
		verdict = &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
		// Regex found nothing locally. Give the AID lane a turn —
		// custom AID policies (e.g. organisation-specific PII rules)
		// may match where the bundled regex pack didn't.
		if aid := a.hookAIDInspect(ctx, "message", content); aid != nil && aid.Action != "allow" && aid.Action != "" {
			verdict = mergeWithAIDVerdict(nil, aid)
		}
	} else {
		severity := HighestSeverity(ruleFindings)
		confidence := HighestConfidence(ruleFindings, severity)

		action := guardrailActionAllow
		if enforceable := enforceableRuleFindings(ruleFindings); len(enforceable) > 0 {
			action = guardrailRuntimeActionForConnector(
				a.scannerCfg,
				req.Connector,
				HighestSeverity(enforceable),
				strings.EqualFold(req.Direction, "outbound"),
			)
		}

		reasons := make([]string, 0, minInt(len(ruleFindings), 5))
		for i, f := range ruleFindings {
			if i >= 5 {
				break
			}
			reasons = append(reasons, f.RuleID+":"+f.Title)
		}

		verdict = &ToolInspectVerdict{
			Action:           action,
			Severity:         severity,
			Confidence:       confidence,
			Reason:           fmt.Sprintf("matched: %s", strings.Join(reasons, ", ")),
			Findings:         FindingStrings(ruleFindings),
			DetailedFindings: ruleFindings,
		}

		// AID lane: forward the message content to Cisco AI Defense when
		// configured. mergeWithAIDVerdict escalates strictness — AID block
		// trumps regex alert, AID HIGH trumps regex MEDIUM, etc. Lane is a
		// no-op when no client is wired.
		if aid := a.hookAIDInspect(ctx, "message", content); aid != nil {
			verdict = mergeWithAIDVerdict(verdict, aid)
		}
	}

	// Judge lane: forward the content to the LLM judge for connectors
	// gated on via guardrail.judge.hook_connectors. Runs after the
	// regex + AID lanes so detection_strategy=regex_judge can skip the
	// LLM round-trip when the local lanes were already decisive.
	if jv := a.hookJudgeInspect(ctx, req, content, verdict); jv != nil {
		verdict = mergeWithJudgeVerdict(verdict, jv)
	}
	if req.contentScope == ruleContentScopeSource {
		clampSourceScopeVerdict(verdict)
	}
	return verdict
}

// clampSourceScopeVerdict keeps physically verified detector/test source
// matches visible without letting any local, AID, judge, or managed-AID lane
// turn source review into a hook action. Source content is still useful
// telemetry, so findings are retained and uniformly marked LOW and
// detection-only rather than suppressed.
func clampSourceScopeVerdict(verdict *ToolInspectVerdict) {
	if verdict == nil {
		return
	}
	detected := guardrailSeverityRank(verdict.Severity) > severityNone ||
		len(verdict.Findings) > 0 || len(verdict.DetailedFindings) > 0 ||
		!strings.EqualFold(strings.TrimSpace(verdict.Action), guardrailActionAllow)
	verdict.Action = guardrailActionAllow
	verdict.RawAction = ""
	verdict.WouldBlock = false
	verdict.ApprovalTimeoutMS = 0
	if detected {
		verdict.Severity = "LOW"
	} else {
		verdict.Severity = "NONE"
	}
	for i := range verdict.DetailedFindings {
		verdict.DetailedFindings[i].Severity = "LOW"
		verdict.DetailedFindings[i].enforcement = findingEnforcementDetectionOnly
	}
}

// maxConcurrentHookJudges bounds concurrent hook-lane judge executions
// (see APIServer.hookJudgeSem). Mirrors EventRouter.judgeSem's bound on
// the proxy lane.
const maxConcurrentHookJudges = 16

// defaultHookJudgeTimeout caps the hook-lane judge round-trip when
// guardrail.judge.hook_timeout is unset. Hook scripts call the gateway
// with curl --max-time 10 (see connector/hooks/*-hook.sh); the proxy
// lane's 30s judge default would let the client sever the connection
// before a verdict lands. 5s leaves headroom for the regex/AID phases
// plus response rendering.
const defaultHookJudgeTimeout = 5 * time.Second

// hookJudgeInspect runs the LLM judge on hook-lane message content for
// connectors gated on via guardrail.judge.hook_connectors. It maps the
// request direction to the proxy lane's judge vocabulary and delegates
// to runHookJudge; for message content the strategy direction and the
// judge direction coincide. Returns nil whenever the judge produces no
// usable verdict (see runHookJudge) so the caller keeps the regex/AID
// verdict unchanged.
func (a *APIServer) hookJudgeInspect(ctx context.Context, req *ToolInspectRequest, content string, current *ToolInspectVerdict) *ScanVerdict {
	// RunJudges speaks the proxy lane's direction vocabulary: "prompt"
	// selects the injection + exfil (+ PII-prompt) judges, "completion"
	// the PII-completion judge. Hook tool_result content is tool/model
	// output — completion-shaped, matching how the proxy judges tool
	// results in inspectToolResult.
	direction := "completion"
	if strings.EqualFold(req.Direction, "prompt") {
		direction = "prompt"
	}
	// Message content threads the caller ctx so the generic /inspect/tool
	// endpoint's 200ms deadline still short-circuits the judge below.
	return a.runHookJudge(ctx, direction, direction, req.Connector, content, req.Tool, current)
}

// runHookJudge is the shared hook-lane judge core for all three hook
// surfaces — message content, tool-call args (J3-3b), and tool output
// (J3-3d). It is the opt-in gate: the judge runs only when the operator
// has BOTH listed the connector in guardrail.judge.hook_connectors AND
// opted the surface's direction into a judge strategy via
// EffectiveStrategy(strategyDirection). The shipped default (regex_only)
// returns nil and no LLM round-trip happens.
//
//   - strategyDirection is the operator opt-in surface: "tool_call" for
//     tool-call args, "completion" for tool output / completions,
//     "prompt" for prompts. Maps to the --detection-strategy-* flags
//     fu/setup writes onto `setup guardrail`.
//   - judgeDirection is the proxy-lane vocabulary RunJudges speaks:
//     "prompt" runs injection + exfil (+ PII-prompt); "completion" the
//     PII-completion judge.
//
// The judge round-trip is bounded by its OWN timeout (JudgeConfig.HookTimeout,
// else defaultHookJudgeTimeout) derived from the supplied parent ctx —
// NEVER the 200ms rule-scan cap (J3-3c). Callers that must escape that
// cap (the tool lanes) pass a deadline-free context.Background(),
// mirroring the proxy lane's inspectToolResult; the message lane threads
// its caller ctx so the generic /inspect/tool endpoint's 200ms deadline
// still short-circuits the judge here.
//
// Returns nil — caller keeps the regex/AID verdict (fail-open, the same
// contract as the AID lane) — when: not wired, connector not gated,
// strategy regex_only, regex/AID already decisive under regex_judge,
// caller deadline too short, at capacity, or the judge failed. A judge
// failure/timeout is logged LOUDLY to stderr; the lane never silently
// substitutes a clean pass.
func (a *APIServer) runHookJudge(ctx context.Context, strategyDirection, judgeDirection, connector, content, toolName string, current *ToolInspectVerdict) *ScanVerdict {
	if a == nil || a.hookJudge == nil || a.scannerCfg == nil || content == "" {
		return nil
	}
	jcfg := &a.scannerCfg.Guardrail.Judge
	if !jcfg.HookConnectorEnabled(connector) {
		return nil
	}

	switch a.scannerCfg.Guardrail.EffectiveStrategy(strategyDirection) {
	case "judge_first":
		// Judge always runs.
	case "regex_judge":
		// Mirror the proxy regex_judge semantics: a HIGH+ regex/AID
		// verdict is already decisive, so the LLM round-trip is spent
		// only on content the local lanes couldn't condemn.
		if current != nil && severityRank[strings.ToUpper(current.Severity)] >= severityRank["HIGH"] {
			return nil
		}
	default: // regex_only / unset
		return nil
	}

	// The generic /inspect handlers run under a 200ms deadline
	// (inspectScanTimeout) — no judge round-trip fits, and blowing
	// that deadline would 504 the whole verdict. Skip unless the
	// caller's remaining budget can plausibly carry an LLM call. The
	// tool lanes pass a deadline-free context.Background() so they are
	// never gated out here (J3-3c).
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) < time.Second {
		return nil
	}

	select {
	case a.hookJudgeSem <- struct{}{}:
	default:
		fmt.Fprintf(os.Stderr, "[inspect] hook judge skipped (at capacity) connector=%s direction=%s\n",
			connector, strategyDirection)
		return nil
	}
	defer func() { <-a.hookJudgeSem }()

	timeout := defaultHookJudgeTimeout
	if jcfg.HookTimeout > 0 {
		timeout = time.Duration(jcfg.HookTimeout * float64(time.Second))
	}
	jctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if strings.EqualFold(toolName, "message") {
		toolName = ""
	}
	v := a.hookJudge.RunJudges(jctx, judgeDirection, content, toolName)
	if v == nil || v.JudgeFailed {
		// Degrade LOUD: surface the judge unavailability so operators
		// can see the lane fell back to the regex/AID verdict rather
		// than mistaking the absence of a judge finding for a clean
		// judge pass. Fail-open to the local verdict matches the proxy
		// lane (guardrail.go judge_first fallback) and the AID lane.
		failedScanner := ""
		if v != nil {
			failedScanner = v.Scanner
		}
		fmt.Fprintf(os.Stderr, "[inspect] hook judge unavailable (connector=%s direction=%s scanner=%q); keeping regex/AID verdict\n",
			connector, strategyDirection, failedScanner)
		return nil
	}
	return v
}

func (a *APIServer) handleInspectTool(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ToolInspectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Tool == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tool is required"})
		return
	}
	serverConnector := authenticatedInspectConnector(r.Context())
	if serverConnector == "" {
		serverConnector = canonicalConnectorRulePackKey(a.connectorName())
	}
	requestedConnector := canonicalConnectorRulePackKey(req.Connector)
	if requestedConnector != "" && requestedConnector != serverConnector {
		a.writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "connector does not match authenticated scope",
		})
		return
	}
	req.Connector = serverConnector

	scanTimeout := inspectScanTimeout
	if a.inspectToolScanTimeout > 0 {
		scanTimeout = a.inspectToolScanTimeout
	}
	ctx, cancel := context.WithTimeout(r.Context(), scanTimeout)
	defer cancel()
	workerCtx := deferManagedAIDFailOpenAccounting(ctx)

	fmt.Fprintf(os.Stderr, "[inspect] >>> tool=%q args=%s content_len=%d direction=%s\n",
		req.Tool, redaction.MessageContent(string(req.Args)), len(req.Content), req.Direction)

	t0 := time.Now()

	type verdictResult struct {
		v *ToolInspectVerdict
	}
	ch := make(chan verdictResult, 1)
	workerDone := a.inspectToolWorkerDone
	go func() {
		if workerDone != nil {
			defer workerDone()
		}
		var v *ToolInspectVerdict
		if strings.EqualFold(req.Tool, "message") {
			v = a.inspectMessageContent(workerCtx, &req)
		} else {
			// Pass the 200ms-capped ctx so the tool-call judge lane's
			// deadline guard short-circuits on this generic endpoint
			// (mirroring the message lane); native hook callers go
			// through inspectToolPolicy with a deadline-free context.
			v = a.inspectToolPolicyCtx(workerCtx, &req)
		}
		ch <- verdictResult{v}
	}()

	var verdict *ToolInspectVerdict
	select {
	case res := <-ch:
		verdict = res.v
	case <-ctx.Done():
		// Prefer a verdict that completed at the deadline boundary. Both
		// channels can be ready when a CPU-starved handler is rescheduled;
		// returning 504 in that case discards completed local policy work.
		select {
		case res := <-ch:
			verdict = res.v
		default:
			fmt.Fprintf(os.Stderr, "[inspect] tool scan timeout after %s\n", time.Since(t0))
			a.writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "scan timeout"})
			return
		}
	}

	verdict.applyMode(inspectMode(a.scannerCfg))
	a.resolveOpenClawInspectConfirm(r.Context(), &req, verdict)

	elapsed := time.Since(t0)

	// verdict.Reason is normally composed as "matched: <rule-id>:<title>".
	// Exact compiled-in ID/title pairs are safe metadata, while titles from
	// external scanners can contain matched literals. Display boundaries use
	// the catalog-aware helpers in reason_display.go to distinguish the two.
	safeFindings := make([]string, len(verdict.Findings))
	for i, finding := range verdict.Findings {
		safeFindings[i] = redaction.Reason(finding)
	}
	fmt.Fprintf(os.Stderr, "[inspect] <<< tool=%q action=%s raw_action=%s severity=%s mode=%s would_block=%v confidence=%.2f elapsed=%s reason=%q findings=%v\n",
		req.Tool, verdict.Action, verdict.RawAction, verdict.Severity, verdict.Mode, verdict.WouldBlock,
		verdict.Confidence, elapsed,
		redaction.Reason(verdict.Reason), safeFindings)

	switch verdict.Action {
	case "block":
		fmt.Fprintf(os.Stderr, "[inspect] BLOCKED tool=%q severity=%s reason=%q\n",
			req.Tool, verdict.Severity, redaction.Reason(verdict.Reason))
	case "confirm":
		fmt.Fprintf(os.Stderr, "[inspect] CONFIRM tool=%q severity=%s reason=%q\n",
			req.Tool, verdict.Severity, redaction.Reason(verdict.Reason))
	case "alert":
		fmt.Fprintf(os.Stderr, "[inspect] ALERT tool=%q severity=%s reason=%q\n",
			req.Tool, verdict.Severity, redaction.Reason(verdict.Reason))
	default:
		if verdict.WouldBlock {
			fmt.Fprintf(os.Stderr, "[inspect] OBSERVED tool=%q severity=%s reason=%q (would-block in action mode)\n",
				req.Tool, verdict.Severity, redaction.Reason(verdict.Reason))
		}
	}

	var auditAction string
	switch verdict.Action {
	case "block":
		auditAction = string(audit.ActionInspectToolBlock)
	case "confirm":
		auditAction = string(audit.ActionInspectToolConfirm)
	case "alert":
		auditAction = string(audit.ActionInspectToolAlert)
	default:
		auditAction = string(audit.ActionInspectToolAllow)
	}
	connectorName := a.connectorName()
	a.recordInspectMetricsV8(
		r.Context(), connectorName, connectorName+":"+req.Tool,
		verdict.Action, verdict.Severity, elapsed,
	)
	a.recordGuardrailMetricsV8(
		r.Context(), connectorName, connectorName+":policy-rules", verdict.Action, elapsed,
	)
	targetType := "tool_call"
	if strings.ToLower(req.Tool) == "message" {
		switch strings.ToLower(req.Direction) {
		case "completion", "outbound", "response":
			targetType = "completion"
		case "tool_result", "tool-response":
			targetType = "tool_response"
		default:
			targetType = "prompt"
		}
	}
	evalCtx := a.emitInspectVerdictFindings(r.Context(), "inspect-http",
		"/api/v1/inspect/tool:"+req.Tool, targetType, verdict, elapsed,
		"emit_inspect_tool")
	a.emitInspectTraceV8(r.Context(), req.Tool, targetType, verdict, elapsed, evalCtx)

	requestID := RequestIDFromContext(r.Context())
	auditDetails := fmt.Sprintf("severity=%s confidence=%.2f reason=%s elapsed=%s mode=%s would_block=%v raw_action=%s",
		verdict.Severity, verdict.Confidence, verdict.Reason, elapsed, verdict.Mode, verdict.WouldBlock, verdict.RawAction)
	if requestID != "" {
		auditDetails += fmt.Sprintf(" request_id=%s", requestID)
	}
	auditDetails = appendHookEvaluationDetails(auditDetails, evalCtx)
	_ = a.logger.LogActionCtx(r.Context(), auditAction, req.Tool, auditDetails)

	a.emitCodeGuardTelemetry(r.Context(), &req, verdict, elapsed)

	// Response-body redaction. By default every Evidence string in
	// DetailedFindings and verdict.Reason are replaced with the
	// ForSinkEvidence/ForSinkReason placeholders so a caller that
	// simply GETs the verdict and logs it cannot accidentally echo
	// user PII. Callers who need raw evidence for triage set
	// X-DefenseClaw-Reveal-PII: 1; we record that fact in the
	// canonical compliance history so every reveal is discoverable.
	reveal := wantsReveal(r)
	responseVerdict := verdict.sanitizeForResponse(reveal)
	if reveal {
		// Audit the reveal BEFORE exposing the raw response. The reveal
		// occurrence is deliberately content-free: the preceding canonical
		// guardrail/finding records already contain the source evidence and
		// receive the destination's configured redaction projection. Copying
		// that evidence into this mandatory compliance record would add no
		// forensic value and could expose it through the mandatory floor.
		_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionInspectReveal), req.Tool,
			fmt.Sprintf("severity=%s remote=%s reason_present=%t finding_count=%d",
				verdict.Severity, r.RemoteAddr, strings.TrimSpace(verdict.Reason) != "",
				len(verdict.DetailedFindings)))
	}
	// The worker only classifies the managed AID fail-open reason. Account for
	// it after this handler has selected the allow result; the 504
	// path returns above and deliberately records nothing because installed
	// hooks fail closed on an unreachable gateway.
	a.recordManagedAIDFailOpenForSelectedGenericResult(r.Context(), verdict)
	a.writeJSON(w, http.StatusOK, responseVerdict)
}

func (a *APIServer) resolveOpenClawInspectConfirm(ctx context.Context, req *ToolInspectRequest, verdict *ToolInspectVerdict) {
	if verdict == nil || verdict.Action != guardrailActionConfirm {
		return
	}
	verdict.RawAction = guardrailActionConfirm
	timeout := 60 * time.Second
	if a.scannerCfg != nil && a.scannerCfg.Gateway.ApprovalTimeout > 0 {
		timeout = time.Duration(a.scannerCfg.Gateway.ApprovalTimeout) * time.Second
	}
	verdict.ApprovalTimeoutMS = int(timeout / time.Millisecond)

	// a HIGH-severity tool call that policy escalated
	// to `confirm` MUST NOT be downgraded to `alert` when the caller
	// cannot deliver a human-in-the-loop approval. The previous
	// behavior (alert + would_block=false) caused hook callers that
	// only block on action==block to forward the tool call as audit
	// telemetry. Failing closed here turns "no native approval
	// surface" into a BLOCK with would_block tracking the original
	// confirm decision.
	if !strings.EqualFold(a.connectorName(), "openclaw") {
		verdict.Action = guardrailActionBlock
		verdict.WouldBlock = true
		verdict.Reason = appendVerdictReason(verdict.Reason,
			"human approval unsupported on this connector surface; failing closed")
		if a.logger != nil {
			_ = a.logger.LogActionCtx(ctx, hiltStatusUnsupported, req.Tool, "connector="+a.connectorName())
		}
		return
	}
	if strings.EqualFold(strings.TrimSpace(req.ApprovalSurface), "native") {
		return
	}

	verdict.Action = guardrailActionBlock
	verdict.WouldBlock = true
	verdict.Reason = appendVerdictReason(verdict.Reason,
		"human approval requires native OpenClaw approval; failing closed")
	if a.logger != nil {
		_ = a.logger.LogActionCtx(ctx, hiltStatusUnsupported, req.Tool, "surface="+req.ApprovalSurface)
	}
}

func appendVerdictReason(reason, suffix string) string {
	if strings.TrimSpace(reason) == "" {
		return suffix
	}
	return reason + "; " + suffix
}

// sanitizeForResponse returns a copy of v suitable for the HTTP
// response body. When reveal is false (the default) every Evidence
// field in DetailedFindings is replaced with the
// "<redacted-evidence len=... sha=...>" placeholder AND Reason is
// routed through ForSinkReason. The composed reason is normally
// shaped as "matched: <rule-id>:<title>, …". Exact compiled-in pairs pass
// through via defaultSinkDisplayReason only when no managed override is
// active; if a scanner embeds a matched literal in f.Title, the sink barrier
// still scrubs it.
//
// The original verdict is left untouched so canonical observability producers
// retain the full source data. The unified runtime applies the selected
// redaction profile independently for each destination after routing.
func (v *ToolInspectVerdict) sanitizeForResponse(reveal bool) *ToolInspectVerdict {
	policy := sinkPolicyFor(context.Background(), v.RedactionEnabled)
	if reveal && policy != redaction.SinkPolicyRedact {
		return v
	}
	cp := *v
	cp.Reason = defaultSinkDisplayReason(v.Reason, policy)
	if len(v.DetailedFindings) == 0 {
		return &cp
	}
	cp.DetailedFindings = make([]RuleFinding, len(v.DetailedFindings))
	for i, f := range v.DetailedFindings {
		cp.DetailedFindings[i] = f
		cp.DetailedFindings[i].Evidence = redaction.ForSinkEvidence(f.Evidence, -1, -1)
	}
	return &cp
}

// emitCodeGuardTelemetry records CodeGuard evaluation metrics for every
// supported write operation and emits the existing alert when a finding is
// present. The alert is migrated independently from the generated metrics.
func (a *APIServer) emitCodeGuardTelemetry(
	ctx context.Context,
	req *ToolInspectRequest,
	verdict *ToolInspectVerdict,
	elapsed time.Duration,
) {
	if a == nil || req == nil || verdict == nil {
		return
	}

	tool := strings.ToLower(req.Tool)
	if tool != "write_file" && tool != "edit_file" {
		return
	}

	connectorName := a.connectorName()
	a.recordGuardrailMetricsV8(ctx, connectorName, "codeguard", verdict.Action, elapsed)

	hasCodeGuardFinding := false
	for _, f := range verdict.Findings {
		if strings.HasPrefix(f, "codeguard:") {
			hasCodeGuardFinding = true
			break
		}
	}

	if !hasCodeGuardFinding {
		return
	}

	if verdict.Action == "block" || verdict.Action == "alert" {
		a.recordSecurityAlertMetricV8(
			ctx, connectorName, verdict.Severity, "codeguard-finding", "codeguard",
		)
	}
}
