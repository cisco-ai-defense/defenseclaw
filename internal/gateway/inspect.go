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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
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
	// ToolCallID is the OpenClaw id of the call, sent by the OpenClaw plugin so
	// an enforced block can be tied to the result message of that call (GAP-0644).
	ToolCallID string `json:"tool_call_id,omitempty"`
	// Connector is an optional assertion. The authenticated server route
	// selects the connector generation; a mismatched assertion is rejected.
	Connector     string `json:"connector,omitempty"`
	MCPServerName string `json:"mcp_server_name,omitempty"`
	// BoundedPrefixReview is set by the per-user shell inspect hooks on the
	// bounded review of a call over their size cap (markOversizeUninspected).
	BoundedPrefixReview bool `json:"bounded_prefix_review,omitempty"`
	// toolUseID is set by a connector adapter, never from the wire (see
	// contentScope below).
	toolUseID string
	// toolArgsAreHookEnvelope marks args the connector did not project from a
	// tool payload: the whole hook envelope, session and event keys included.
	toolArgsAreHookEnvelope bool
	// aidToolCallDeclared is set by a connector adapter, never from the wire,
	// when the resolved hook contract declares the tool_call surface in the
	// encoding hookAIDInspectToolCall implements. Without it the invocation is
	// sent to AID as text alone, so an undeclared contract never changes shape.
	aidToolCallDeclared bool
	// toolNameIsLabel marks Tool as a placeholder the adapter filled in because
	// the payload named no tool; it is not sent as a tool call's name.
	toolNameIsLabel bool
	// toolArgsAbsent marks Args as the empty object an adapter fills in when the
	// payload carried no tool input, or a null one; it is not sent as a tool
	// call's arguments.
	toolArgsAbsent bool
	// hookEvent is the agent hook event that produced the request, set by a
	// connector adapter for the AID wire log only.
	hookEvent string
	// contentScope is set only after a connector adapter derives content
	// provenance from its typed hook payload. It is deliberately not accepted
	// from the public inspect wire, where a caller could otherwise promote its
	// own content into the trust-exploit enforcement lane. The zero value keeps
	// the legacy public inspect API; native adapters opt in after establishing a
	// prompt or tool-result boundary.
	contentScope ruleContentScope
	// callerCWD is the agent's working folder from a connector adapter's
	// typed hook payload (never from the public inspect wire). It picks the
	// project of an enrolled account's MCP server (mcpAccountRuntimeBlock).
	callerCWD string
	// skipJudge keeps the LLM judge off content that carries no prompt or
	// tool text of its own, only the name of a file the agent itself keeps
	// (Claude Code FileChanged on ~/.claude.json, GAP-2623). The rule and AID
	// lanes still scan it and the event is still recorded. Set only by a
	// connector adapter, never from the public inspect wire.
	skipJudge bool
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
	// aiDefenseBlock is trusted in-process provenance: it is set only when
	// Cisco AI Defense itself returned a block verdict. Hook finalization uses
	// it to distinguish an enforced AID decision from a later local asset-policy
	// escalation. It is intentionally absent from every caller-controlled wire
	// shape.
	aiDefenseBlock bool
	// managedAIDFailOpenReason is an internal accounting marker. The generic
	// HTTP handler consumes it only after selecting an allow result, so
	// a timed-out request that the connector fails closed cannot be counted as
	// a fail-open allow decision. It is never serialized.
	managedAIDFailOpenReason string
	// laneVerdict reports that a scan lane (Cisco AI Defense, the LLM
	// judge) returned a verdict of its own that is not a plain allow. A
	// lane may block or raise the severity without naming a rule, so the
	// rule IDs and findings alone cannot show that it took part; the
	// sandbox unblock lift (liftUnblockedDestinations) must keep such a
	// verdict. Never serialized.
	laneVerdict bool
	// decisionConfirm reports that the confirm action came from the
	// decision model answering without the LLM judge (cascade 2). Where the
	// agent cannot ask, such a confirm is the HIGH alert the judge mapping
	// gives, not a block (decisionConfirmWithoutAsk). Never serialized.
	decisionConfirm bool
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
// markOversizeUninspected answers a bounded review of an oversized call
// (bounded_prefix_review, from the per-user shell inspect hooks) like the
// native hook route: never a silent allow of a call the gateway read only in
// part. It runs before applyMode, so observe mode warns and audits the call
// and action mode blocks it; a block found in the review stands.
func (v *ToolInspectVerdict) markOversizeUninspected() {
	if v.Action == "block" {
		return
	}
	v.Action = "block"
	v.Severity = "HIGH"
	v.Reason = oversizeUninspectedReason
	v.Findings = append([]string{hookOversizeUninspectedRuleID}, v.Findings...)
}

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
	return a != nil && a.scannerCfg != nil && a.scannerCfg.ManagedAIDOnly()
}

// aidToolCall is a tool invocation sent to AID as a structured tool call.
type aidToolCall struct {
	Connector string
	Event     string
	Name      string
	ID        string
	Args      json.RawMessage
}

// inspectManagedAIDOnly is the managed_enterprise hook-lane inspection
// path: Cisco AI Defense is the only thing that can block. Static
// block/allow lists, MCP-server blocks, connector regex packs, CodeGuard,
// and the LLM judge are all skipped. When AID returns no verdict (unwired /
// down / timeout / token failure — hookAIDInspect returns nil), the request
// fails open with an explicit allow verdict.
func (a *APIServer) inspectManagedAIDOnly(ctx context.Context, toolName, content string) *ToolInspectVerdict {
	return a.inspectManagedAIDOnlyCall(ctx, toolName, content, nil)
}

// inspectManagedAIDOnlyCall is the shared fail-open path: call is nil for
// content, set for a tool invocation.
func (a *APIServer) inspectManagedAIDOnlyCall(
	ctx context.Context,
	toolName, content string,
	call *aidToolCall,
) *ToolInspectVerdict {
	cfg := a.decisionConfig(ctx)
	failOpenReason := aidFailOpenUnavailable
	if call == nil && !managedAIDHookContentIsInspectable(toolName, content) {
		failOpenReason = aidFailOpenNoContent
	} else if call != nil && len(call.Args) == 0 {
		failOpenReason = aidFailOpenNoContent
	} else if a == nil || a.currentCiscoInspector() == nil || cfg == nil ||
		!cfg.CiscoAIDefense.HookSurfaceEnabled() {
		failOpenReason = aidFailOpenUnwired
	}
	var aid *ScanVerdict
	if call != nil {
		aid = a.hookAIDInspectToolCall(ctx, *call, content)
	} else {
		aid = a.hookAIDInspect(ctx, toolName, content)
	}
	if aid == nil {
		// Fail-open surface: managed_enterprise's local detectors are
		// demoted, so a nil AID verdict means this inspection ends
		// with no enforceable decision. Every occurrence must be
		// operator-visible per the "no silent skip" contract — the
		// metric-only accounting below is retained for /health and
		// long-term dashboards, but the stderr line is what a human
		// tailing gateway.err.log during triage will actually see.
		logManagedAIDSkip(string(failOpenReason), "hookAIDInspect returned no verdict — see prior [cisco-ai-defense] error / structured event for cause")
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
	inspector := a.currentCiscoInspector()
	if inspector == nil {
		return nil
	}
	if cfg := a.decisionConfig(ctx); cfg == nil || !cfg.CiscoAIDefense.HookSurfaceEnabled() {
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
	defer yieldHookRunSlot(ctx)()
	return inspector.Inspect(ctx, []ChatMessage{
		{Role: "user", Content: hookAIDToolText(toolName, content)},
	})
}

// toolCallArgsCarryable reports whether the invocation can stand as tool-call
// fields: the connector's contract declares the encoding, the connector named
// the tool, and the arguments are a JSON object it projected from its own tool
// payload. A blank or placeholder name would put a made-up name in
// function.name. JSON null decodes into a map without error, but it is not an
// object, and AID's rule engine fails the tool-call rules on it.
func toolCallArgsCarryable(req *ToolInspectRequest) bool {
	return toolCallNotCarriedReason(req) == ""
}

// toolCallNotCarriedReason names why an invocation goes to AID as text alone,
// in the order toolCallArgsCarryable checks; "" when it can be carried.
func toolCallNotCarriedReason(req *ToolInspectRequest) string {
	switch {
	case req == nil || req.Direction != "tool_call":
		return "not_a_tool_call"
	case !req.aidToolCallDeclared:
		return "contract_undeclared"
	case req.toolArgsAreHookEnvelope:
		return "hook_envelope_args"
	case req.toolNameIsLabel:
		return "placeholder_tool_name"
	case strings.TrimSpace(req.Tool) == "":
		return "blank_tool_name"
	case req.toolArgsAbsent:
		return "args_absent"
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(req.Args, &object) != nil || object == nil {
		return "args_not_object"
	}
	return ""
}

// aidHookSurfaceWired reports whether a hook inspection reaches AID at all, so
// the wire log below is written only for requests that are actually sent.
func (a *APIServer) aidHookSurfaceWired(ctx context.Context) bool {
	if a.currentCiscoInspector() == nil {
		return false
	}
	cfg := a.decisionConfig(ctx)
	return cfg != nil && cfg.CiscoAIDefense.HookSurfaceEnabled()
}

// logAIDToolCallTextOnly records that a tool invocation went to AID as the
// text form alone, and why. Names only, never argument values. A tool name the
// adapter filled in as a label, or a blank one, is shown as <none>.
func (a *APIServer) logAIDToolCallTextOnly(
	ctx context.Context,
	connectorName, event, toolName string,
	nameIsLabel bool,
	reason string,
) {
	if reason == "" || reason == "not_a_tool_call" || !a.aidHookSurfaceWired(ctx) {
		return
	}
	tool := aidLogQuoted(toolName)
	if nameIsLabel || strings.TrimSpace(toolName) == "" {
		tool = "<none>"
	}
	fmt.Fprintf(os.Stderr, "[aid] PreToolUse sent as text only: connector=%s event=%s tool=%s reason=%s\n",
		connectorName, aidLogEvent(event), tool, reason)
}

func aidLogEvent(event string) string {
	if strings.TrimSpace(event) == "" {
		return "<unknown>"
	}
	return aidLogField(event)
}

// The event, tool name, id and argument keys of an [aid] line come from the
// agent and are bounded only by the request body cap; these limits keep one
// call's line short.
const (
	aidLogFieldMaxBytes = 128
	aidLogMaxArgKeys    = 32
)

// aidLogField is s cut to aidLogFieldMaxBytes on a rune boundary, marked with
// "..." when it was cut.
func aidLogField(s string) string {
	if len(s) <= aidLogFieldMaxBytes {
		return s
	}
	return truncateToRuneBoundary(s, aidLogFieldMaxBytes) + "..."
}

// aidLogQuoted is s quoted, so a crafted value cannot forge a line, and then
// cut to aidLogFieldMaxBytes: escaping can make a value up to four times
// longer, so the bound applies to the escaped form. A cut ends in `..."`.
func aidLogQuoted(s string) string {
	q := strconv.Quote(s)
	if len(q) <= aidLogFieldMaxBytes {
		return q
	}
	return truncateToRuneBoundary(q, aidLogFieldMaxBytes) + `..."`
}

// logAIDToolCallCarried records the shape of a tool call sent to AID: the
// tool name, the id and whether the agent reported it, the argument keys and
// the message order. Never argument values, which carry commands and content.
func logAIDToolCallCarried(call aidToolCall, wireID string) {
	idSource := "agent"
	if call.ID == "" {
		idSource = "derived"
	}
	var object map[string]json.RawMessage
	_ = json.Unmarshal(call.Args, &object)
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	moreKeys := ""
	if len(keys) > aidLogMaxArgKeys {
		moreKeys = fmt.Sprintf(" (+%d more)", len(keys)-aidLogMaxArgKeys)
		keys = keys[:aidLogMaxArgKeys]
	}
	for i := range keys {
		keys[i] = aidLogQuoted(keys[i])
	}
	// The name, id and argument keys come from the agent: aidLogQuoted quotes
	// and bounds them.
	fmt.Fprintf(os.Stderr, "[aid] PreToolUse sent as a tool call: connector=%s event=%s tool=%s id=%s (%s) arg_keys=[%s]%s wire=%s messages=[assistant:tool_calls, user:text]\n",
		call.Connector, aidLogEvent(call.Event), aidLogQuoted(call.Name), aidLogQuoted(wireID), idSource,
		strings.Join(keys, " "), moreKeys, connector.AIDWireVersionChatToolCalls)
}

// hookAIDInspectTool sends the invocation as a tool call ahead of the text form,
// and as text alone when the arguments cannot be carried as fields.
func (a *APIServer) hookAIDInspectTool(
	ctx context.Context,
	req *ToolInspectRequest,
	toolName, argsStr string,
) *ScanVerdict {
	// hookAIDInspect and hookAIDInspectToolCall return nil without a wired
	// hook surface too; checking first skips parsing the arguments.
	if !a.aidHookSurfaceWired(ctx) {
		return nil
	}
	if reason := toolCallNotCarriedReason(req); reason != "" {
		a.logAIDToolCallTextOnly(ctx, req.Connector, req.hookEvent, toolName, req.toolNameIsLabel, reason)
		return a.hookAIDInspect(ctx, toolName, argsStr)
	}
	return a.hookAIDInspectToolCall(ctx, aidToolCall{
		Connector: req.Connector,
		Event:     req.hookEvent,
		Name:      toolName,
		ID:        req.toolUseID,
		Args:      req.Args,
	}, argsStr)
}

// aidToolCallMaxBytes bounds the tool call added beside the text form. Both
// carry the arguments, so a larger one is sent as text alone, as before:
// doubling the arguments could push the request past AID's 10 MiB body limit,
// which fails the inspection open.
const aidToolCallMaxBytes = 2 << 20

// toolCallWireID is the tool call's id. The chat schema requires a non-empty
// one, so an invocation the agent did not identify is given a "dc-" id derived
// from its own content, which also marks it as not the agent's.
func toolCallWireID(call aidToolCall) string {
	if call.ID != "" {
		return call.ID
	}
	sum := sha256.Sum256(append([]byte(call.Name+"\x00"), call.Args...))
	return "dc-" + hex.EncodeToString(sum[:8])
}

// hookAIDInspectToolCall sends the invocation as an assistant tool call, with
// arguments as a JSON string, followed by the message hookAIDInspect would send
// for it. That user message is unchanged and stays last: AID takes the
// direction from the last role, so the request path, its policies and the
// text rules' input are what they were, and the tool call only adds to them.
func (a *APIServer) hookAIDInspectToolCall(
	ctx context.Context,
	call aidToolCall,
	content string,
) *ScanVerdict {
	inspector := a.currentCiscoInspector()
	if inspector == nil {
		return nil
	}
	if cfg := a.decisionConfig(ctx); cfg == nil || !cfg.CiscoAIDefense.HookSurfaceEnabled() {
		return nil
	}
	if len(call.Args) == 0 {
		return nil
	}
	if strings.TrimSpace(call.Name) == "" {
		a.logAIDToolCallTextOnly(ctx, call.Connector, call.Event, call.Name, false, "blank_tool_name")
		return a.hookAIDInspect(ctx, call.Name, content)
	}
	wireID := toolCallWireID(call)
	toolCalls, err := json.Marshal([]map[string]interface{}{{
		"id":   wireID,
		"type": "function",
		"function": map[string]interface{}{
			"name":      call.Name,
			"arguments": string(call.Args),
		},
	}})
	if err != nil {
		return nil
	}
	if len(toolCalls) > aidToolCallMaxBytes {
		a.logAIDToolCallTextOnly(ctx, call.Connector, call.Event, call.Name, false, "oversized")
		return a.hookAIDInspect(ctx, call.Name, content)
	}
	logAIDToolCallCarried(call, wireID)
	defer yieldHookRunSlot(ctx)()
	return inspector.Inspect(ctx, []ChatMessage{
		{Role: "assistant", ToolCalls: toolCalls},
		{Role: "user", Content: hookAIDToolText(call.Name, content)},
	})
}

// hookAIDToolText is the flattened form AID's text classifiers read.
func hookAIDToolText(toolName, content string) string {
	if toolName != "" && toolName != "message" {
		return fmt.Sprintf("Tool call: %s\n%s", toolName, content)
	}
	return content
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
	merged := mergeWithLaneVerdict(local, aid, "ai-defense:")
	if merged != nil && aid != nil && strings.EqualFold(strings.TrimSpace(aid.Action), "block") {
		merged.aiDefenseBlock = true
	}
	return merged
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
	if rank(aid.Action) > 0 || sevRank(aid.Severity) > 0 || len(aid.Findings) > 0 {
		local.laneVerdict = true
	}
	// AID-only escalation path: escalate the action when AID is
	// stricter, escalate the severity when AID is stricter, append
	// findings + reason so the audit trail shows both lanes.
	if rank(aid.Action) > rank(local.Action) {
		local.Action = aid.Action
		local.decisionConfirm = aid.decisionConfirm && strings.EqualFold(aid.Action, guardrailActionConfirm)
	} else if rank(aid.Action) == rank(local.Action) && !aid.decisionConfirm {
		// Another lane confirms too: the confirm is not the decision
		// model's alone.
		local.decisionConfirm = false
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
		// A judge finding is titled by its category and keeps the
		// severity of the judge that reported it, not the strictest one
		// of the judges merged into the lane verdict (GAP-1886).
		for i, f := range aid.Findings {
			rf := RuleFinding{
				RuleID:   f,
				Title:    f,
				Severity: aid.Severity,
				Tags:     []string{strings.TrimSuffix(findingTag, ":")},
			}
			if s := aid.findingSeverity[f]; s != "" {
				rf.Severity = s
			}
			if i < len(aid.findingSeverities) && aid.findingSeverities[i] != "" {
				rf.Severity = aid.findingSeverities[i]
			}
			if i < len(aid.findingProfiles) {
				rf.profile = aid.findingProfiles[i]
			}
			if findingTag == "llm-judge:" {
				if title := judgeFindingTitle(f); title != "" {
					rf.Title = title
				}
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

// inspectToolTrustedShellCWD is the working directory a shell tool call on
// /inspect/tool names for its command, when it is absolute; the session's is
// not known there.
func inspectToolTrustedShellCWD(dir string) string {
	if filepath.IsAbs(dir) || strings.HasPrefix(dir, "/") {
		return dir
	}
	return ""
}

// inspectToolPolicyCtx is inspectToolPolicy with an explicit context for
// the judge lane's deadline guard. The generic /inspect/tool endpoint
// (handleInspectTool) passes its 200ms-capped ctx so the judge
// short-circuits there exactly as the message lane does; native hook
// callers reach this through inspectToolPolicy with context.Background().
func (a *APIServer) inspectToolPolicyCtx(ctx context.Context, req *ToolInspectRequest) *ToolInspectVerdict {
	actionTool := req.Tool
	if strings.EqualFold(strings.TrimSpace(req.Connector), "opencode") {
		actionTool = agentHookTrustedActionTool(req.Connector, req.Tool, "")
	}
	action := trustedActionRequest{
		Input: actionfacts.Input{
			Tool:       actionTool,
			Args:       req.Args,
			ActiveHome: hookActiveHome(ctx),
		},
		LegacyText:         string(req.Args),
		Connector:          req.Connector,
		EnforcementCapable: true,
	}
	if args, dir, ok := connector.TrustedShellArgs(req.Connector, req.Tool, req.Args); ok {
		// OpenClaw's exec tool sends execution controls (yieldMs, timeout,
		// workdir, ...) next to the command. Left in the arguments they made
		// the parse partial, so every command block rule was detection-only
		// (GAP-1450). The directory is the command's working directory when
		// it is absolute; the session's is not known here.
		action.Input.Args = args
		action.Input.CWD = inspectToolTrustedShellCWD(dir)
		// The conflicting-keys check reads the arguments as the call carried
		// them and projects each candidate the same way (GAP-0678).
		base := action.Input
		action.conflictSource = &conflictingToolArgumentSource{
			raw: req.Args,
			project: func(raw json.RawMessage) actionfacts.Input {
				candidate := base
				candidate.Args, candidate.CWD = raw, ""
				if args, dir, ok := connector.TrustedShellArgs(req.Connector, req.Tool, raw); ok {
					candidate.Args, candidate.CWD = args, inspectToolTrustedShellCWD(dir)
				}
				return candidate
			},
		}
	}
	ctx = a.withInstructionStartup(ctx, req.Connector, req.SessionID,
		a.applyInstructionInspectStartup(ctx, req.Connector, req.SessionID, action.Input.CWD))
	if trustedShimArgvTool(req.Tool) {
		// Authenticated PATH shims have one closed argv envelope. If that
		// envelope is malformed, extended, or names another executable, raw
		// fallback findings remain useful telemetry but cannot authorize a deny.
		action.EnforcementCapable = false
	}
	if argv, ok := parseTrustedShimArgv(req.Tool, req.Args); ok {
		action.Input = actionfacts.Input{
			Tool:       req.Tool,
			Argv:       argv,
			ActiveHome: hookActiveHome(ctx),
		}
		action.LegacyText = serializeArgvForLegacyScan(argv)
		action.EnforcementCapable = true
		return a.inspectTrustedToolPolicyCtx(ctx, req, action)
	}
	// An argument TrustedShellArgs leaves for the parser (OpenClaw's env,
	// elevated, host, node) keeps the parse partial, so a CRITICAL command
	// rule stayed detection-only and the command ran (GAP-1450). As for a
	// sandbox's shell calls, the command is also judged on its own, and that
	// verdict only ever adds to the call's.
	if command, ok := connector.ShellCommandArgs(req.Connector, req.Tool, req.Args); ok {
		return a.inspectSandboxShellToolPolicyCtx(ctx, req, action, command, action.Input.Tool)
	}
	return a.inspectTrustedToolPolicyCtx(ctx, req, action)
}

// parseTrustedShimArgv recognizes the exact argument envelope emitted by the
// authenticated PATH shims. A malformed, extended, or mismatched envelope is
// deliberately rejected so inspectToolPolicyCtx keeps its non-authoritative
// Args projection and owner-local regex fallback.
func parseTrustedShimArgv(tool string, raw json.RawMessage) ([]string, bool) {
	if !trustedShimArgvTool(tool) {
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

func trustedShimArgvTool(tool string) bool {
	switch tool {
	case "curl", "wget", "ssh", "nc", "pip", "npm":
		return true
	default:
		return false
	}
}

func (a *APIServer) inspectTrustedToolPolicyCtx(
	ctx context.Context,
	req *ToolInspectRequest,
	action trustedActionRequest,
) *ToolInspectVerdict {
	action.StrictPolicy = a.strictPolicyTierForHook(ctx, action.Connector)
	action.ManagedInstall = a.managedInstallForHook(ctx)
	// managed_enterprise: Cisco AI Defense is the sole decision-maker.
	// Skip static block/allow + MCP-server block, connector regex packs,
	// CodeGuard, and the judge lane; AID inspects the tool call directly
	// and a nil AID verdict fails open. See inspectManagedAIDOnly.
	if a.managedAIDOnly() {
		if reason := toolCallNotCarriedReason(req); reason != "" {
			a.logAIDToolCallTextOnly(ctx, req.Connector, req.hookEvent, req.Tool, req.toolNameIsLabel, reason)
			return a.inspectManagedAIDOnly(ctx, req.Tool, string(req.Args))
		}
		return a.inspectManagedAIDOnlyCall(ctx, req.Tool, string(req.Args), &aidToolCall{
			Connector: req.Connector,
			Event:     req.hookEvent,
			Name:      req.Tool,
			ID:        req.toolUseID,
			Args:      req.Args,
		})
	}

	// Static block/allow list takes priority — checked before any rule
	// scanning. Connector-scoped (@C/T) entries resolve before the bare
	// global entry, mirroring the sidecar lane and the PolicyEngine helpers:
	//   block @C/T → allow @C/T → block T → allow T → scan
	// The lists are config.yaml asset_policy (tool and mcp).
	// Keep all static checks in this decision on the request snapshot. The
	// Secure Client path keeps its pre-1.0 live policy source (issue #1092).
	policyConfig := a.decisionConfig(ctx)
	policySource := func() *config.Config { return policyConfig }
	if a.scannerCfg != nil && a.scannerCfg.SecureClientIntegration() {
		policySource = a.liveConfig
	}
	pe := enforce.NewPolicyEngine(a.store).WithConfig(policySource)
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
	// An enrolled account's own admission verdict (GAP-0216).
	if deny, reason := a.mcpAccountRuntimeBlock(ctx, pe, req); deny {
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
	// An explicit allow skips ordinary rule/pattern/AID/judge scanning. A
	// resolved high-severity write is still inspected: allowing the tool name
	// cannot authorize an active instruction-file mutation. Write tools also
	// keep CodeGuard inspection of their content (D2).
	allowed, err := pe.IsToolAllowedForConnector(req.Tool, req.Connector)
	if err != nil {
		return toolPolicyLookupErrorVerdict("inspect", "allow-list", req.Tool, req.Connector, err)
	}
	if allowed {
		cfg := a.decisionConfig(ctx)
		if (cfg == nil || !cfg.SecureClientIntegration()) &&
			(len(provedHighWriteFindings(ctx, action, nil)) != 0 ||
				len(agentHookConfigFindings(ctx, action, nil)) != 0) {
			allowed = false
		}
	}
	if allowed {
		if !isWriteToolName(strings.ToLower(req.Tool)) {
			return &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{"STATIC-ALLOW"}}
		}
		if cg := a.runCodeGuardOnArgsWithProvenance(ctx, req); len(cg.findings) > 0 {
			return a.codeGuardOnlyVerdict(ctx, req, cg, true, action.EnforcementCapable)
		}
		return &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{"STATIC-ALLOW"}}
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
	// The live shadow run of the effect lane records through the audit log
	// (guardrail.cascade.lanes.effects=shadow, GAP-0256); it never changes the verdict.
	action.recordEffectShadow = func(res EffectShadowResult) {
		a.recordEffectShadow(ctx, firstNonEmpty(req.Connector, action.Connector), res)
	}
	// CodeGuard: scan file content for any file-write tool.
	//
	// the legacy gate matched only the canonical
	// `write_file` / `edit_file` names, but native connector events
	// emit aliases like Claude Code "Write" / "Edit" / "MultiEdit",
	// Codex "patch", and Cursor "applyDiff". Those bypassed CodeGuard
	// entirely while carrying the same code payload. We accept any
	// recognised file-write alias (case-insensitive). The scan runs beside
	// the rule dispatch (startCodeGuardOnArgs, GAP-2284).
	tool := strings.ToLower(toolName)
	isWriteTool := isWriteToolName(tool)
	var waitCodeGuard func() codeGuardArgsScan
	if isWriteTool {
		waitCodeGuard = a.startCodeGuardOnArgs(ctx, req)
	}
	ruleFindings := inspectDispatchTrustedAction(ctx, action)
	ruleFindings = provedHighWriteFindings(ctx, action, ruleFindings)
	// A Secure Client install keeps its own tool policy (GAP-0048 adds no
	// finding there).
	if cfg := a.decisionConfig(ctx); cfg == nil || !cfg.SecureClientIntegration() {
		ruleFindings = agentHookConfigFindings(ctx, action, ruleFindings)
	}
	// An MCP or app tool is read as effects (internal/toolshape): the path it
	// names, its SQL, code, settings and send destinations (rel-1-0-10:GAP-0016).
	ruleFindings = nonShellToolFindings(ctx, action, ruleFindings, req.MCPServerName)
	ruleFindings = shellToolFindings(ctx, action, ruleFindings)
	var cgScan codeGuardArgsScan
	if waitCodeGuard != nil {
		cgScan = waitCodeGuard()
	}
	cgFindings := codeGuardRuleFindings(cgScan, true, action.EnforcementCapable)

	var verdict *ToolInspectVerdict
	if len(ruleFindings) == 0 && len(cgFindings) == 0 {
		verdict = &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
		// Regex + CodeGuard found nothing locally. Give the AID lane a
		// turn — operators with custom AID policies (e.g. block
		// `createJiraIssue`, throttle `addComment`) want their rules to
		// fire even when no DefenseClaw built-in pattern matched.
		if aid := a.hookAIDInspectTool(ctx, req, toolName, argsStr); aid != nil && aid.Action != "allow" && aid.Action != "" {
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

		runtimeAction := profileMeetActionForFindings(
			ctx, a.decisionConfig(ctx), req.Connector, ruleFindings, true, false,
		)
		// CodeGuard's findings carry no member and apply to every member.
		// The rule findings decided above, each under its own member: their
		// severity folded in here let an action member enforce an observe
		// member's rule (GAP-1708).
		if _, codeGuardSeverity := aggregateCodeGuardSeverity(cgFindings, "NONE", "NONE"); codeGuardSeverity != "NONE" {
			codeGuardAction := profileMeetActionForSeverity(
				ctx, a.decisionConfig(ctx), req.Connector, codeGuardSeverity, true, false,
			)
			runtimeAction = strongerGuardrailAction(runtimeAction, codeGuardAction)
		}

		reasons := make([]string, 0, minInt(len(ruleFindings), 5))
		for i, f := range ruleFindings {
			if i >= 5 {
				break
			}
			reasons = append(reasons, f.RuleID+":"+f.Title)
		}
		// A CodeGuard-only hit left the reason an empty "matched: ", which
		// the agent notice showed as a redaction token (GAP-2029).
		for _, cf := range cgFindings {
			if len(reasons) >= 5 {
				break
			}
			reasons = append(reasons, cf.RuleID+":"+cf.Title)
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
		detectionOnly := len(ruleFindings) > 0 && len(cgFindings) == 0
		for _, finding := range ruleFindings {
			if finding.enforcement != findingEnforcementDetectionOnly {
				detectionOnly = false
				break
			}
		}
		if detectionOnly {
			if cfg := a.decisionConfig(ctx); cfg == nil || !cfg.SecureClientIntegration() {
				verdict.Reason = "detection-only: tool-call patterns alone cannot block; " + verdict.Reason
			}
		}

		// AID lane: also forward to Cisco AI Defense when the operator has
		// configured a key. Strictest verdict wins via mergeWithAIDVerdict.
		// The lane is silent when no AID client is wired or when
		// ScanHookSurface=false.
		if aid := a.hookAIDInspectTool(ctx, req, toolName, argsStr); aid != nil {
			verdict = mergeWithAIDVerdict(verdict, aid)
		}
	}

	// Judge lane (J3-3b): forward the tool args to the LLM judge for
	// connectors opted into the tool_call direction via
	// guardrail.judge.hook_connectors + EffectiveStrategy("tool_call").
	// Tool-call args use the dedicated tool-injection judge. Sending this
	// surface through the ordinary prompt judges loses the tool's semantic
	// boundary: it can mistake source-code strings for instructions while
	// missing destructive or exfiltrating command effects. The shipped
	// default (regex_only) returns nil and no LLM round-trip happens. Runs
	// after the regex/AID lanes so regex_judge can skip the round-trip when
	// the local lanes already condemned the call.
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
	return a.runCodeGuardOnArgsWithProvenance(context.Background(), req).findings
}

type codeGuardArgsScan struct {
	findings []scanner.Finding
	complete bool
}

func (a *APIServer) runCodeGuardOnArgsWithProvenance(ctx context.Context, req *ToolInspectRequest) codeGuardArgsScan {
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
	if cfg := a.decisionConfig(ctx); cfg != nil {
		rulesDir = cfg.Scanners.CodeGuard
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
	ctx context.Context,
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
		action = profileMeetActionForSeverity(ctx, a.decisionConfig(ctx), req.Connector, enforceableSeverity, true, false)
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

// withoutBlockMessageEcho drops the configured block message from text the
// agent hands back: a tool result that carries the denial DefenseClaw
// returned, or the reply that repeats it. A contact address in that message
// raised a PII alert on every block (GAP-0400). Only that exact
// operator-authored text is replaced, by a space so the text around it is
// not joined, and the rest is still scanned, so nothing else is hidden.
func withoutBlockMessageEcho(cfg *config.Config, connector, content string) string {
	if cfg == nil {
		return content
	}
	message := strings.TrimSpace(cfg.EffectiveBlockMessageForConnector(connector))
	if len(message) < minEchoedBlockMessageLen || !strings.Contains(content, message) {
		return content
	}
	return strings.ReplaceAll(content, message, " ")
}

// minEchoedBlockMessageLen keeps a very short block message from removing
// ordinary words from scanned text.
const minEchoedBlockMessageLen = 16

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

	if req.Direction == "response" || req.Direction == "tool_result" {
		content = withoutBlockMessageEcho(a.decisionConfig(ctx), req.Connector, content)
	}
	if content == "" {
		return &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	}

	// Outbound messages get the full scan — tool name "message" for context.
	// Routed through the request's connector so each connector scans against
	// its own rule pack (empty ⇒ process-global default set).
	// Prompts and tool results can contain invisible separators or letters
	// that resemble Latin script. Keep this extra view confined to trust rules.
	folded := ""
	if cfg := a.decisionConfig(ctx); cfg == nil || !cfg.SecureClientIntegration() {
		if view := trustPatternText(content); view != content {
			folded = view
		}
	}
	ruleFindings := messageRuleFindings(snapshotRulePackGenerationFor(ctx, req.Connector), content, folded, req.contentScope, !ManagedEnterpriseActive())

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
			action = profileMeetActionForFindings(
				ctx, a.decisionConfig(ctx), req.Connector, enforceable,
				strings.EqualFold(req.Direction, "outbound"), true,
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
	if req.skipJudge {
		// No judge round-trip (see ToolInspectRequest.skipJudge).
	} else if jv := a.hookJudgeInspect(ctx, req, content, verdict); jv != nil {
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
	// Source-only content is never enforceable. Do not let a cloud block
	// observed while scanning trusted detector/test source survive as AID
	// enforcement provenance when the untrusted segment is merged later.
	verdict.aiDefenseBlock = false
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
// before a verdict lands. 8s fits Bedrock-class judge latency (Haiku 4.5
// injection calls measured at p90 4.2s, max 5.0s; GAP-1475/GAP-1488) and
// still leaves 2s for the regex/AID phases plus response rendering.
const defaultHookJudgeTimeout = 8 * time.Second

// hookJudgeTimeout is guardrail.judge.hook_timeout, else
// defaultHookJudgeTimeout.
func hookJudgeTimeout(cfg *config.Config) time.Duration {
	if cfg != nil && cfg.Guardrail.Judge.HookTimeout > 0 {
		return time.Duration(cfg.Guardrail.Judge.HookTimeout * float64(time.Second))
	}
	return defaultHookJudgeTimeout
}

type hookJudgeBudgetKey struct{}

// withHookJudgeBudget gives every hook judge call under ctx one shared end:
// the calls of one hook (a parallel Copilot toolCalls envelope) answer in
// the one round trip the hook client waits for, so their judge calls cannot
// add up past it (GAP-1835).
func withHookJudgeBudget(ctx context.Context, end time.Time) context.Context {
	return context.WithValue(ctx, hookJudgeBudgetKey{}, end)
}

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

// connectorRulePack is the composed rule pack the request scans connector
// with: its guardrail profile scope when one applies, preloaded or loaded
// lazily (GAP-1526), else the connector scope of the request's generation
// (guardrail.rules with every connector layer), else the global pack.
func (a *APIServer) connectorRulePack(ctx context.Context, connector string) *guardrail.RulePack {
	connector = canonicalConnectorRulePackKey(connector)
	if pack := resolvedGuardrailProfileFrom(ctx).rulePack(connector); pack != nil {
		return pack
	}
	g := a.decisionGeneration(ctx)
	if g == nil {
		return nil
	}
	if pack := g.RulePacks["conn:"+connector]; pack != nil {
		return pack
	}
	return g.RulePacks["global"]
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
//   - judgeDirection is the proxy-lane vocabulary RunJudges speaks for
//     message/tool-result content. Tool calls bypass it and use RunToolJudge.
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
	if resolved := resolvedGuardrailProfileFrom(ctx); resolved != nil && resolved.set != nil {
		if meet := resolved.evaluationMeet(); meet != nil {
			// The hook client has one round-trip budget even when several
			// profiles judge. Start every member under that same deadline so
			// a slow observer cannot spend an action member's entire budget.
			judgeCtx, cancel := context.WithTimeout(ctx, hookJudgeTimeout(a.decisionConfig(ctx)))
			defer cancel()
			results := make([]*ScanVerdict, len(meet.members))
			var judges sync.WaitGroup
			for i, member := range meet.members {
				judges.Add(1)
				go func() {
					defer judges.Done()
					memberCtx := meetMemberContext(judgeCtx, resolved, member)
					memberCurrent := meetMemberJudgeCurrent(memberCtx, connector, current, member)
					results[i] = a.runHookJudgeSingle(memberCtx, strategyDirection, judgeDirection, connector, content, toolName, memberCurrent)
				}()
			}
			judges.Wait()
			var combined *ScanVerdict
			for i, member := range meet.members {
				verdict := results[i]
				if verdict == nil {
					continue
				}
				if !configBlocksOn(resolved.set.profileConfig(member), connector, requestProfilePath(ctx)) &&
					(verdict.Action == guardrailActionBlock || verdict.Action == guardrailActionConfirm) {
					verdict.Action = guardrailActionAlert
				}
				if combined == nil {
					combined = &ScanVerdict{Action: guardrailActionAllow, Severity: "NONE"}
				}
				raises := strongerGuardrailAction(combined.Action, verdict.Action) != combined.Action
				combined.decisionConfirm = meetDecisionConfirm(combined.decisionConfirm, combined.Action, verdict, raises)
				if raises {
					combined.Action, combined.Reason = verdict.Action, verdict.Reason
				}
				if guardrailSeverityRank(verdict.Severity) > guardrailSeverityRank(combined.Severity) {
					combined.Severity = verdict.Severity
				}
				if combined.Scanner == "" {
					combined.Scanner = verdict.Scanner
				}
				if verdict.Confidence > combined.Confidence {
					combined.Confidence = verdict.Confidence
				}
				combined.Findings = append(combined.Findings, verdict.Findings...)
				for _, finding := range verdict.Findings {
					combined.findingProfiles = append(combined.findingProfiles, member)
					severity := verdict.Severity
					if own := verdict.findingSeverity[finding]; own != "" {
						severity = own
					}
					combined.findingSeverities = append(combined.findingSeverities, severity)
				}
				combined.ScannerSources = appendUniqueStrings(combined.ScannerSources, verdict.ScannerSources...)
			}
			return combined
		}
	}
	return a.runHookJudgeSingle(ctx, strategyDirection, judgeDirection, connector, content, toolName, current)
}

func meetMemberJudgeCurrent(ctx context.Context, connector string, current *ToolInspectVerdict, member string) *ToolInspectVerdict {
	if current == nil || len(current.DetailedFindings) == 0 {
		return current
	}
	var own []RuleFinding
	for _, finding := range current.DetailedFindings {
		if finding.profile == "" || finding.profile == member {
			own = append(own, finding)
		}
	}
	if len(own) == 0 {
		return nil
	}
	memberConfig := resolvedGuardrailProfileFrom(ctx).derived
	return &ToolInspectVerdict{
		Action:   profileMeetActionForFindings(ctx, memberConfig, connector, own, true, true),
		Severity: HighestSeverity(own),
		// The member's own findings decide whether its verdict is decisive
		// (regexJudgeLocalVerdictDecisive), as for a single profile.
		DetailedFindings: own,
	}
}

func (a *APIServer) runHookJudgeSingle(ctx context.Context, strategyDirection, judgeDirection, connector, content, toolName string, current *ToolInspectVerdict) (out *ScanVerdict) {
	if content == "" {
		return nil
	}
	// Gate on the configuration of the generation the judge came from: the
	// request pins one, so a reload cannot pair a new gate with a nil or
	// previous judge. A start-time scannerCfg can have another connector gate.
	cfg := a.decisionConfig(ctx)
	if g := pinnedGeneration(ctx); g.published() && cfg != nil && !cfg.SecureClientIntegration() {
		cfg = a.decisionConfigFrom(ctx, g.Config)
	}
	if cfg == nil {
		return nil
	}
	judge, strategy := a.hookLaneJudge(ctx, cfg, strategyDirection, connector)
	if judge == nil {
		return nil
	}
	if strings.EqualFold(strategyDirection, "tool_call") && hookJudgeSkipsNoEffectCall(connector, toolName, current) {
		return nil
	}

	switch strategy {
	case "judge_first":
		// Judge always runs.
	case "regex_judge":
		if regexJudgeLocalVerdictDecisive(cfg, current) {
			return nil
		}
	default: // regex_only / unset
		return nil
	}

	// A decision-model floor set while the judge runs is the answer when
	// the judge is late (GAP-0392).
	floorSlot := &decisionFloorSlot{}
	ctx = withDecisionFloorSlot(ctx, floorSlot)
	// A rule finding is a floor: the decision model cannot skip the judge on
	// a call the rules flagged (escalate-on-confirm). Read it here, before
	// the judge can run apart from the answer: the caller folds this run's
	// verdict (an escalated fail-closed refusal included) into current while
	// a late judge is still running.
	ruleFloor := rulesFlagged(current)
	// The decision model answers before the judge's own gates (deadline,
	// hook budget, judge slots), so a confident block exists under load
	// (S7 sysone review round 3, P3-1). Action mode only: an observe answer
	// does not wait for any model.
	var prepass *decisionPrepass
	if strings.EqualFold(strategyDirection, "tool_call") &&
		sandboxHookMode(ctx, connector, cfg.HookModeForConnector(connector)) == "action" {
		ctx, prepass = judge.prepareDecision(withDecisionRuleFloor(ctx, ruleFloor), toolName, content)
	}
	// noJudgeVerdict answers a call the judge cannot take: the decision
	// model's answer alone (an allow, the HIGH floor of a confident block,
	// or nothing), else the rule verdict.
	noJudgeVerdict := func() *ScanVerdict {
		if prepass == nil {
			return nil
		}
		v := judge.runToolJudgeSample(withJudgeUnavailable(withDecisionRuleFloor(ctx, ruleFloor)), toolName, content, prepass.sample)
		return judgeReviewOnlyAudit(cfg, connector, ruleFloor, hookJudgeLaneVerdict(cfg, connector, strategyDirection, v))
	}

	// The generic /inspect handlers run under a 200ms deadline
	// (inspectScanTimeout) — no judge round-trip fits, and blowing
	// that deadline would 504 the whole verdict. Skip unless the
	// caller's remaining budget can plausibly carry an LLM call. The
	// tool lanes pass a deadline-free context.Background() so they are
	// never gated out here (J3-3c).
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) < time.Second {
		fmt.Fprintf(os.Stderr, "[inspect] hook judge skipped (deadline too short) connector=%s direction=%s; keeping regex/AID verdict\n",
			connector, strategyDirection)
		return noJudgeVerdict()
	}

	if strategy == "regex_judge" && regexJudgeEscalatedCritical(cfg, current) &&
		sandboxHookMode(ctx, connector, cfg.HookModeForConnector(connector)) == "action" &&
		cfg.EffectiveHookOutageFailModeForConnector(connector) == "closed" {
		// The call is here only because its CRITICAL finding cannot block on
		// its own: the judge is what decides it. When the judge gives no
		// verdict (an error, a timeout, a late answer, no capacity or hook
		// budget left), the call follows the connector's hook fail mode, as
		// for a gateway outage: closed (strict tier, managed hosts, or an
		// explicit closed) refuses it; open (the default and permissive
		// tiers of a per-user install) keeps the rule verdict with the
		// fallback warning and metric below. Secure Client never escalates.
		defer func() {
			// A decision-model floor is not a judge verdict: it never
			// replaces the closed-mode refusal (review round 3, P3-2).
			if out == nil || out.decisionFloorOnly {
				fmt.Fprintf(os.Stderr, "[inspect] hook judge gave no verdict on an escalated CRITICAL finding connector=%s direction=%s; hook_fail_mode closed: refusing\n",
					connector, strategyDirection)
				out = escalatedJudgeFailClosedVerdict()
			}
		}()
	}

	timeout := hookJudgeTimeout(cfg)
	if end, ok := ctx.Value(hookJudgeBudgetKey{}).(time.Time); ok {
		// The hook's earlier calls spent the shared judge budget: keep the
		// regex/AID verdict, as for any judge that cannot answer in time.
		left := time.Until(end)
		if left < time.Second {
			fmt.Fprintf(os.Stderr, "[inspect] hook judge skipped (hook judge budget spent) connector=%s direction=%s; keeping regex/AID verdict\n",
				connector, strategyDirection)
			a.recordHookJudgeFallback(ctx, connector, judgeFallbackBudget)
			return noJudgeVerdict()
		}
		timeout = min(timeout, left)
	}

	a.hookJudgeSemOnce.Do(func() { a.hookJudgeSem = make(chan struct{}, maxConcurrentHookJudges) })
	select {
	case a.hookJudgeSem <- struct{}{}:
	default:
		fmt.Fprintf(os.Stderr, "[inspect] hook judge skipped (at capacity) connector=%s direction=%s\n",
			connector, strategyDirection)
		a.recordHookJudgeFallback(ctx, connector, judgeFallbackBusy)
		return noJudgeVerdict()
	}
	if strings.EqualFold(toolName, "message") {
		toolName = ""
	}
	pack := a.connectorRulePack(ctx, connector)
	// One judge run reports at most one fallback (#1395): a late answer and
	// the failure of the same run that arrives after it are one fallback.
	var fallbackOnce sync.Once
	fallback := func(reason string) {
		fallbackOnce.Do(func() { a.recordHookJudgeFallback(context.WithoutCancel(ctx), connector, reason) })
	}
	lateVerdict := func() *ScanVerdict {
		if v := floorSlot.get(); v != nil {
			return judgeReviewOnlyAudit(cfg, connector, ruleFloor, hookJudgeLaneVerdict(cfg, connector, strategyDirection, v))
		}
		return nil
	}
	call := func(callCtx context.Context) *ScanVerdict {
		jctx, cancel := context.WithTimeout(callCtx, timeout)
		defer cancel()
		jctx = withJudgeSuppressionPack(jctx, pack)
		var v *ScanVerdict
		if strings.EqualFold(strategyDirection, "tool_call") {
			jctx = withDecisionRuleFloor(jctx, ruleFloor)
			v = judge.RunToolJudge(jctx, toolName, content)
		} else {
			v = judge.RunJudges(jctx, judgeDirection, content, toolName)
		}
		if reason := hookJudgeCallFallback(v, jctx); reason != "" {
			fallback(reason)
		}
		return v
	}

	answerEnd, bounded := hookJudgeAnswerEnd(ctx)
	if !bounded {
		defer func() { <-a.hookJudgeSem }()
		resume := yieldHookRunSlot(ctx)
		v := call(ctx)
		resume()
		return judgeReviewOnlyAudit(cfg, connector, ruleFloor, hookJudgeLaneVerdict(cfg, connector, strategyDirection, v))
	}

	// A bounded action hook cancels the model request when its answer
	// window closes. An observe hook returns immediately while its judge
	// runs until that same window; it still records an answer in time.
	observe := sandboxHookMode(ctx, connector, cfg.HookModeForConnector(connector)) != "action"
	var callCtx context.Context
	var cancel context.CancelFunc
	if observe {
		callCtx, cancel = context.WithDeadline(context.WithoutCancel(ctx), answerEnd)
	} else {
		callCtx, cancel = context.WithCancel(ctx)
		defer cancel()
	}
	done := make(chan *ScanVerdict, 1)
	go func() {
		defer func() { <-a.hookJudgeSem }()
		if observe {
			defer cancel()
		}
		done <- call(callCtx)
	}()
	if observe {
		fmt.Fprintf(os.Stderr, "[inspect] hook judge does not hold the answer (observe) connector=%s direction=%s\n",
			connector, strategyDirection)
		return nil
	}
	left := time.Until(answerEnd)
	if left <= 0 {
		fmt.Fprintf(os.Stderr, "[inspect] hook judge late (hook answer window spent) connector=%s direction=%s; keeping regex/AID verdict\n",
			connector, strategyDirection)
		fallback(judgeFallbackLate)
		return lateVerdict()
	}
	wait := time.NewTimer(left)
	defer wait.Stop()
	resume := yieldHookRunSlot(ctx)
	defer resume()
	select {
	case v := <-done:
		return judgeReviewOnlyAudit(cfg, connector, ruleFloor, hookJudgeLaneVerdict(cfg, connector, strategyDirection, v))
	case <-wait.C:
	case <-ctx.Done():
	}
	fmt.Fprintf(os.Stderr, "[inspect] hook judge late (over the %s hook answer window) connector=%s direction=%s; keeping regex/AID verdict\n",
		hookJudgeAnswerWindow, connector, strategyDirection)
	fallback(judgeFallbackLate)
	// A decision-model floor already set stands (the late judge can only
	// have added to it).
	return lateVerdict()
}

// claudeCodeNoEffectTools are Claude Code built-ins whose call acts on nothing
// outside the agent: ToolSearch loads tool definitions and TodoWrite edits the
// agent's own task list. The judge read the tool names in a ToolSearch query
// ("select:mcp__gmail__search_messages,...") as data access and blocked 17 of
// 127 benign ToolSearch calls on the s3 corpus (Gemma 3 27B judge).
var claudeCodeNoEffectTools = map[string]bool{"ToolSearch": true, "TodoWrite": true}

// hookJudgeSkipsNoEffectCall reports a Claude Code no-effect built-in the
// rules did not flag: the judge and the decision model are not asked, and the
// call stays out of the session history later samples carry. Only Claude
// Code: other connectors pass MCP tool names without a prefix (Cursor's
// beforeMCPExecution), where a TodoWrite tool can write to a remote service.
// A flagged call is judged as before, so the rule floor and the escalated
// fail-closed refusal hold.
func hookJudgeSkipsNoEffectCall(connector, toolName string, current *ToolInspectVerdict) bool {
	return config.NormalizeConnectorName(connector) == "claudecode" && claudeCodeNoEffectTools[toolName] && !rulesFlagged(current)
}

// regexJudgeLocalVerdictDecisive reports whether the rule/AID verdict settles
// the call under regex_judge, so the judge is not asked: the verdict already
// blocks, or a finding that can enforce is CRITICAL. A HIGH verdict that only
// alerts (block_at CRITICAL) is not decisive, so the judge runs and the
// stronger verdict wins (GAP-1677). Neither is a CRITICAL finding that cannot
// block: a detection-only or alert-only tool-call finding (a pattern match
// whose effect the parser did not prove) left the judge out of exactly the
// calls the rules flag but cannot decide, and they ran. Secure Client keeps
// the verdict severity (issue #1092).
//
// Nor is the evaluation-limit finding the profile maps by tier (an input read
// up to a cap, a reader failure): it is a floor, not a verdict. Where it only
// alerts (the default and permissive packs) the judge still decides where it
// is configured, and the floor stands when the judge fails or answers lower;
// where it blocks (strict) the verdict already blocks (rel-1-0-10:GAP-0320).
func regexJudgeLocalVerdictDecisive(cfg *config.Config, current *ToolInspectVerdict) bool {
	if current == nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(current.Action), guardrailActionBlock) {
		return true
	}
	severity := current.Severity
	if len(current.DetailedFindings) > 0 && (cfg == nil || !cfg.SecureClientIntegration()) {
		rest, _ := withoutEnforcingEvaluationLimit(enforceableRuleFindings(current.DetailedFindings))
		severity = HighestSeverity(rest)
	}
	return severityRank[strings.ToUpper(severity)] >= severityRank["CRITICAL"]
}

// regexJudgeEscalatedCritical reports a call that reaches the judge under
// regex_judge only because its CRITICAL findings cannot enforce
// (regexJudgeLocalVerdictDecisive): before that rule the call was decisive
// and skipped the judge.
//
// The evaluation-limit finding that can enforce or alerts is not such a
// finding: it is the floor of a truncated call, which stands when the judge
// gives no verdict, so a judge outage under hook_fail_mode closed does not
// raise it to a refusal (rel-1-0-10:GAP-0320).
func regexJudgeEscalatedCritical(cfg *config.Config, current *ToolInspectVerdict) bool {
	if current == nil || (cfg != nil && cfg.SecureClientIntegration()) || regexJudgeLocalVerdictDecisive(cfg, current) {
		return false
	}
	severity := current.Severity
	if len(current.DetailedFindings) > 0 {
		severity = HighestSeverity(slices.DeleteFunc(slices.Clone(current.DetailedFindings), func(finding RuleFinding) bool {
			return profileMappedLimitFinding(finding) && (finding.contributesToEnforcement() || finding.contributesToAlertOnly())
		}))
	}
	return severityRank[strings.ToUpper(severity)] >= severityRank["CRITICAL"]
}

// escalatedJudgeUnavailableFinding names the refusal of an escalated call
// whose judge gave no verdict under hook_fail_mode closed.
const escalatedJudgeUnavailableFinding = "JUDGE-UNAVAILABLE-ESCALATED"

func escalatedJudgeFailClosedVerdict() *ScanVerdict {
	return &ScanVerdict{
		Action:   guardrailActionBlock,
		Severity: "CRITICAL",
		Reason: "judge-unavailable: a CRITICAL finding the rules cannot prove needs the LLM judge, " +
			"which gave no verdict; hook_fail_mode is closed",
		Findings:       []string{escalatedJudgeUnavailableFinding},
		Scanner:        "llm-judge",
		ScannerSources: []string{"llm-judge"},
	}
}

// meetDecisionConfirm is the decisionConfirm of a profile meet after member
// verdict v: v's own when v raises the action to a confirm, cleared when v
// confirms at the same action for another reason, else unchanged. Only the
// decision model's cascade-2 lane confirms on the hook lane today, so the
// clear is a guard for any other confirming lane.
func meetDecisionConfirm(current bool, action string, v *ScanVerdict, raises bool) bool {
	if raises {
		return v.decisionConfirm && v.Action == guardrailActionConfirm
	}
	if v.Action == action && !v.decisionConfirm {
		return false
	}
	return current
}

// hookLaneJudge picks the judge of one hook-lane call and the detection
// strategy it runs under, or nil when no model judges the call:
//   - the LLM judge (with the decision model in front when one is on, cascade
//     3) for a connector in guardrail.judge.hook_connectors under a judge
//     strategy;
//   - else, for a tool call of a connector in decision_model.hook_connectors,
//     the decision model alone (cascade 2). It runs like regex_judge: a rule
//     verdict that already blocks, or has a CRITICAL finding that can
//     enforce, is decisive (regexJudgeLocalVerdictDecisive); judge_first
//     runs it on every call;
//   - else nothing (rules only).
func (a *APIServer) hookLaneJudge(ctx context.Context, cfg *config.Config, strategyDirection, connector string) (*LLMJudge, string) {
	strategy := cfg.Guardrail.EffectiveStrategy(strategyDirection)
	if judge := a.judgeFor(ctx); judge != nil && cfg.Guardrail.Judge.HookConnectorEnabled(connector) &&
		(strategy == "judge_first" || strategy == "regex_judge") {
		return judge, strategy
	}
	if !strings.EqualFold(strategyDirection, "tool_call") || cfg.SecureClientIntegration() ||
		!cfg.DecisionModel.AnswersAlone(connector) {
		return nil, ""
	}
	judge := a.decisionJudgeFor(ctx)
	if judge == nil {
		return nil, ""
	}
	if strategy != "judge_first" {
		strategy = "regex_judge"
	}
	return judge, strategy
}

// judgeReviewOnlyAudit makes a lone review finding of the tool judge audit
// only in the default pack (owner decision 2026-11-13, GAP-0045): when the
// judge's only finding is one needs_review category (MEDIUM, nothing
// actionable) and the rules did not flag the call, the call is allowed. The
// finding stays on the verdict, so the hook records it (the judge event and
// the scan finding rows) without an alert. Strict and permissive keep their
// levels, a call the rules flagged keeps the alert, and HIGH and CRITICAL
// judge verdicts are unchanged. Secure Client keeps the judge action.
func judgeReviewOnlyAudit(cfg *config.Config, connector string, ruleFlagged bool, v *ScanVerdict) *ScanVerdict {
	// The mark alone is not trusted: a merged verdict (the decision model's
	// HIGH floor over a lone judge finding) can copy it, so the verdict must
	// still be one MEDIUM finding.
	if v == nil || !v.reviewOnly || ruleFlagged || cfg == nil || cfg.SecureClientIntegration() ||
		!strings.EqualFold(v.Severity, "MEDIUM") || len(v.Findings) != 1 {
		return v
	}
	// The posture of the pack whose levels mapped the verdict
	// (resolveThresholds): the connector's effective pack, application
	// protection overlay included.
	ref := cfg.EffectiveRulePackRefForConnector(connector)
	if packPostureFor(cfg, ref, cfg.ResolveRulePackDir(ref)) != "default" {
		return v
	}
	if normalizedGuardrailAction(v.Action) != guardrailActionAlert {
		return v
	}
	out := *v
	out.Action = guardrailActionAllow
	out.Reason = strings.TrimSpace(out.Reason + " (audit only: a lone review finding of the judge in the default pack)")
	return &out
}

// hookJudgeLaneVerdict is the hook-lane verdict of judge result v: nil when
// the judge gave none (the caller keeps the regex/AID verdict), else v with
// its action set by the connector block_at / alert_at.
func hookJudgeLaneVerdict(cfg *config.Config, connector, strategyDirection string, v *ScanVerdict) *ScanVerdict {
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
	if !cfg.SecureClientIntegration() {
		// The judge severity goes through block_at / alert_at like every
		// other finding: the judges block any HIGH verdict on their own,
		// which blocked a plain read at the default block_at CRITICAL
		// (GAP-0235). Secure Client keeps the judge action (issue #1092).
		out := *v
		out.Action = guardrailContentAction(cfg, connector, v.Severity, false)
		if v.decisionConfirm {
			out.Action = decisionModelConfirmAction(cfg, connector, v.Severity)
		}
		return &out
	}
	return v
}

func (a *APIServer) handleInspectTool(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.refuseProfileInspect(w, r, "/api/v1/inspect/tool", "inspect-tool-block", "tool") {
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
	r = r.WithContext(openClawInspectIdentity(r.Context(), serverConnector))

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
	// The strict install-window decision is independent of the scanner.
	// Decide it on the request goroutine so a saturated scanner cannot turn
	// this required refusal into a scan timeout.
	installVerdict := &ToolInspectVerdict{}
	a.strictInstallWindowInspect(r.Context(), serverConnector, &req, installVerdict)
	installBlocked := installVerdict.Action == "block"
	if installBlocked {
		ch <- verdictResult{installVerdict}
	} else {
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
	}

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

	if !installBlocked {
		if req.BoundedPrefixReview {
			verdict.markOversizeUninspected()
		}
		verdict.applyMode(inspectMode(a.decisionConfig(r.Context()), serverConnector))
		a.resolveOpenClawInspectConfirm(r.Context(), &req, verdict)
		// A lock that appeared during the scan still decides this request.
		a.strictInstallWindowInspect(r.Context(), serverConnector, &req, verdict)
	}

	// Count the check against the authenticated connector so /health (and the
	// TUI's "0 requests ... verify your agent is dialing the gateway port"
	// notice) sees OpenClaw's exec checks, which arrive only here (GAP-1617).
	if a.recordsConnectorHealth(r.Context()) {
		a.health.RecordToolInspectionFor(serverConnector)
		if verdict.Action == "block" {
			a.health.RecordToolBlockFor(serverConnector)
		}
	}

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
	// Findings name the connector the call was authenticated for, and the
	// connector and tool as their target, as hook findings do: an OpenClaw
	// block was an alert with no connector or target, so `alerts
	// --connector openclaw` did not find it (GAP-1451).
	findingCtx := r.Context()
	if env := audit.EnvelopeFromContext(findingCtx); env.Connector == "" && req.Connector != "" {
		env.Connector = req.Connector
		findingCtx = audit.ContextWithEnvelope(findingCtx, env)
	}
	evalCtx := a.emitInspectVerdictFindings(findingCtx, "inspect-http",
		hookEvaluationTarget(req.Connector, req.Tool), targetType, verdict, elapsed,
		"emit_inspect_tool")
	a.emitInspectTraceV8(r.Context(), req.Tool, targetType, verdict, elapsed, evalCtx)
	if targetType == "tool_call" && strings.EqualFold(firstNonEmpty(req.Connector, connectorName), "openclaw") {
		// The event router puts the decision on the call's tool span
		// (GAP-1930).
		if outcome, ok := hookGuardrailOutcomeFor(verdict.Action, verdict.Severity, verdict.Reason, evalCtx.RuleIDs); ok {
			meta := hookDecisionMetricMeta(r.Context(), connectorName)
			rememberOpenClawToolOutcome(firstNonEmpty(meta.SessionID, req.SessionID), meta.RunID, req.Tool, req.Args, outcome,
				AgentIdentityFromContext(r.Context()))
		}
	}

	requestID := RequestIDFromContext(r.Context())
	auditDetails := fmt.Sprintf("severity=%s confidence=%.2f reason=%s elapsed=%s mode=%s would_block=%v raw_action=%s",
		verdict.Severity, verdict.Confidence, verdict.Reason, elapsed, verdict.Mode, verdict.WouldBlock, verdict.RawAction)
	if requestID != "" {
		auditDetails += fmt.Sprintf(" request_id=%s", requestID)
	}
	auditDetails = appendHookEvaluationDetails(auditDetails, evalCtx)
	toolEvent := a.inspectToolAuditEvent(r, auditAction, req.Tool, auditDetails)
	if verdict.Action != "allow" && verdict.Severity != "" && verdict.Severity != "NONE" {
		// A block, confirm or alert row carries the verdict's severity.
		toolEvent.Severity = verdict.Severity
	}
	// A server built without an audit logger (the deterministic benchmark
	// harness and unit servers; a running gateway always has one) has no
	// audit record to lose, so its verdict stands: the hook routes skip
	// errHookAuditNotConfigured and a proxy without an observability
	// runtime reports no evaluation-log error, for the same reason.
	var auditErr error
	if a.logger != nil {
		auditErr = a.logger.LogEventCtx(r.Context(), toolEvent)
	}
	if auditErr != nil {
		// The tier rule of the hook routes (GAP-0593): strict, managed and
		// sandbox calls fail closed; a default or permissive allow stays
		// allowed with the degraded-audit warning.
		denied := a.inspectAuditFailureVerdict(r.Context(), serverConnector, &req, verdict)
		if denied && a.recordsConnectorHealth(r.Context()) {
			a.health.RecordToolBlockFor(serverConnector)
		}
		fmt.Fprintf(os.Stderr, "[inspect] inspect audit persistence failed tool=%q action=%s denied_for_audit=%t: %v\n",
			req.Tool, verdict.Action, denied, auditErr)
	}

	// The proxy shows an enforced OpenClaw block on the reply that follows it,
	// whichever tool made the call and whichever step made the block, so this
	// is decided on the final verdict, after a failed audit write may have
	// turned an allow into a block (GAP-0644). Secure Client answers stay as
	// they were.
	if strings.EqualFold(firstNonEmpty(req.Connector, connectorName), "openclaw") &&
		openClawNoticeAllowed(a.decisionConfig(r.Context())) {
		if session := strings.TrimSpace(req.SessionID); verdict.Action == "block" && verdict.Mode == "action" {
			rememberOpenClawBlockNotice(req.Tool, req.ToolCallID, session, evalCtx.RuleIDs, verdict.Reason)
		} else {
			// Not a block: the call id is noted so that a block under the
			// same id is known to be ambiguous.
			observeOpenClawToolCall(req.ToolCallID)
		}
	}

	a.emitCodeGuardTelemetry(r.Context(), &req, verdict, elapsed)

	// Response-body redaction. By default every Evidence string in
	// DetailedFindings and verdict.Reason are replaced with the
	// ForSinkEvidence/ForSinkReason placeholders so a caller that
	// simply GETs the verdict and logs it cannot accidentally echo
	// user PII. Callers who need raw evidence for triage set
	// X-DefenseClaw-Reveal-PII: 1; we record that fact in the
	// canonical compliance history so every reveal is discoverable.
	// The worker only classifies the managed AID fail-open reason. Account for
	// it after this handler has selected the allow result; the 504
	// path returns above and deliberately records nothing because installed
	// hooks fail closed on an unreachable gateway.
	a.recordManagedAIDFailOpenForSelectedGenericResult(r.Context(), verdict)
	response := verdict
	// Secure Client answers stay byte-identical to origin/main (issue
	// #1092, GAP-2137): the GAP-1602 evidence fill is for the other
	// profiles only.
	if cfg := a.decisionConfig(r.Context()); cfg == nil || !cfg.SecureClientIntegration() {
		response = inspectToolResponseEvidence(verdict, req.Args)
	}
	a.writeInspectVerdict(w, r, "/api/v1/inspect/tool", req.Tool, response)
}

// inspectToolResponseEvidence gives each finding of the response that names
// no matched text (a semantic rule decides on the parsed call, not a text
// match) the call it judged as its evidence: the command of a shell call,
// else the arguments. The response redacts it unless the caller asks for
// raw evidence (X-DefenseClaw-Reveal-PII: 1, GAP-1602). The audit and
// telemetry records keep the verdict as decided.
func inspectToolResponseEvidence(verdict *ToolInspectVerdict, args json.RawMessage) *ToolInspectVerdict {
	if verdict == nil || len(verdict.DetailedFindings) == 0 {
		return verdict
	}
	text := string(args)
	if command, present, valid := trustedTopLevelCommandField(args); valid && present && strings.TrimSpace(command) != "" {
		text = command
	}
	evidence := sanitizeEvidence(text)
	if strings.TrimSpace(evidence) == "" {
		return verdict
	}
	cp := *verdict
	cp.DetailedFindings = append([]RuleFinding(nil), verdict.DetailedFindings...)
	for i := range cp.DetailedFindings {
		if cp.DetailedFindings[i].Evidence == "" {
			cp.DetailedFindings[i].Evidence = evidence
		}
	}
	return &cp
}

// writeInspectVerdict is the only response boundary for direct inspect routes
// that can reveal matched evidence. The content-free reveal record must be
// saved first; a failed audit write cannot authorize a raw response.
func (a *APIServer) writeInspectVerdict(w http.ResponseWriter, r *http.Request, route, target string, verdict *ToolInspectVerdict) {
	reveal := wantsReveal(r)
	if reveal {
		details := fmt.Sprintf("severity=%s remote=%s reason_present=%t finding_count=%d",
			verdict.Severity, r.RemoteAddr, strings.TrimSpace(verdict.Reason) != "",
			len(verdict.DetailedFindings))
		event := a.inspectAuditEvent(r, route, string(audit.ActionInspectReveal), target, details)
		if err := a.logger.LogEventCtx(r.Context(), event); err != nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "reveal audit unavailable"})
			return
		}
	}
	a.writeJSON(w, http.StatusOK, verdict.sanitizeForResponse(reveal))
}

// inspectToolAuditEvent is the inspect-tool-* audit row.
func (a *APIServer) inspectToolAuditEvent(r *http.Request, action, tool, details string) audit.Event {
	return a.inspectAuditEvent(r, "/api/v1/inspect/tool", action, tool, details)
}

// inspectAuditEvent is the audit row of a direct /api/v1/inspect/* call. It
// names the connector the request was authenticated for (the configured
// connector when the request carries none), the route, and the verified
// caller, so an administrator can attribute direct inspect calls to the
// account that made them.
func (a *APIServer) inspectAuditEvent(r *http.Request, route, action, target, details string) audit.Event {
	ctx := r.Context()
	connectorName := authenticatedInspectConnector(ctx)
	if connectorName == "" {
		connectorName = a.connectorName()
	}
	structured := map[string]any{"route": route}
	if connectorName != "" {
		structured["connector"] = connectorName
	}
	auditCallerIdentity(ctx).addTo(structured)
	if identityFactsEnabled.Load() {
		if id, verified := agentIdentityFromContext(ctx); verified {
			structured["defenseclaw.agent.identity.id"] = id
		}
	}
	return audit.Event{
		Action:     action,
		Target:     target,
		Details:    details,
		Severity:   "INFO",
		Connector:  connectorName,
		Structured: structured,
	}
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
		verdict.Reason = appendVerdictReason(verdict.Reason, approvalUnsupportedNote)
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
	verdict.Reason = appendVerdictReason(verdict.Reason, approvalNativeOpenClawNote)
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
	cp.Reason = agentVerdictReason(v.Action, v.Reason, defaultSinkDisplayReason(v.Reason, policy), policy)
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

// messageRuleFindings is the rule scan of an inspected message with
// generation: every rule on content (scanRaw; scope as for
// scanContentRuleCategoryWithGeneration), then the trust rules on folded
// ("" for none), the same content with invisible separators and look-alike
// letters folded, for a rule the first pass did not find. A strictest
// combination of profiles runs it with each member's own rules and keeps
// every member's finding, so even distinct definitions of one rule ID keep
// their separate audit provenance.
func messageRuleFindings(generation *compiledRulePackCategories, content, folded string, scope ruleContentScope, scanRaw bool) []RuleFinding {
	if generation != nil && len(generation.members) > 0 {
		var out []RuleFinding
		for i, member := range generation.members {
			findings := messageRuleFindings(member, content, folded, scope, scanRaw)
			if i < len(generation.memberNames) {
				for j := range findings {
					findings[j].profile = generation.memberNames[i]
				}
			}
			out = append(out, findings...)
		}
		return out
	}
	var findings []RuleFinding
	if scanRaw {
		if scope != ruleContentScopeAll {
			findings = scanContentRuleCategoryWithGeneration(generation, content, "message", scope, "")
		} else {
			findings = scanRuleGeneration(generation, content, "message", ruleScanOptions{})
		}
	}
	if folded == "" {
		return findings
	}
	seen := make(map[string]bool, len(findings))
	for _, finding := range findings {
		seen[finding.RuleID] = true
	}
	for _, finding := range scanRuleGeneration(generation, folded, "message", ruleScanOptions{
		contentScope: scope, onlyCategory: "trust-exploit",
	}) {
		if !seen[finding.RuleID] {
			findings = append(findings, finding)
			seen[finding.RuleID] = true
		}
	}
	return findings
}
