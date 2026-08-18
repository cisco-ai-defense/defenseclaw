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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/gateway/notifier"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// runGitListMaxBytes caps the bytes we will read from a `git`
// invocation. A monorepo with O(100k) tracked files comfortably fits
// inside 8 MiB; anything larger almost certainly indicates a runaway
// repo or hostile state and would otherwise balloon the gateway's
// resident memory because cmd.Output() reads all of stdout into RAM.
const runGitListMaxBytes = 8 * 1024 * 1024

// A directory result can enter source scope only after a bounded, physical
// walk proves that every possible descendant is still repository-owned test,
// fixture, or guardrail source material. The caps keep a PostToolUse
// classification from turning into an unbounded repository scan.
const (
	codexTrustedSourceTreeMaxEntries = 4096
	codexTrustedSourceTreeMaxBytes   = 64 * 1024 * 1024
	codexTrustedSourceTreeMaxDepth   = 16

	// Observe-mode chat warnings are advisory UI, not canonical evidence.
	// Keep their duplicate cache short-lived and strictly bounded while audit
	// and finding emission continue for every hook evaluation.
	codexAdditionalContextDedupWindow     = 5 * time.Minute
	codexAdditionalContextDedupMaxEntries = 512
)

var errCodexUntrustedSourceTree = errors.New("untrusted source tree")

type codexAdditionalContextEntry struct {
	key  [sha256.Size]byte
	seen time.Time
}

type codexHookRequest struct {
	HookEventName        string                 `json:"hook_event_name"`
	SessionID            string                 `json:"session_id,omitempty"`
	TurnID               string                 `json:"turn_id,omitempty"`
	TranscriptPath       string                 `json:"transcript_path,omitempty"`
	CWD                  string                 `json:"cwd,omitempty"`
	Model                string                 `json:"model,omitempty"`
	Source               string                 `json:"source,omitempty"`
	ToolName             string                 `json:"tool_name,omitempty"`
	MCPServerName        string                 `json:"mcp_server_name,omitempty"`
	ToolUseID            string                 `json:"tool_use_id,omitempty"`
	ToolInput            map[string]interface{} `json:"tool_input,omitempty"`
	ToolResponse         interface{}            `json:"tool_response,omitempty"`
	Prompt               string                 `json:"prompt,omitempty"`
	AgentID              string                 `json:"agent_id,omitempty"`
	AgentType            string                 `json:"agent_type,omitempty"`
	StopHookActive       bool                   `json:"stop_hook_active,omitempty"`
	LastAssistantMessage string                 `json:"last_assistant_message,omitempty"`
	ScanComponents       bool                   `json:"scan_components,omitempty"`
	Bridge               map[string]interface{} `json:"bridge,omitempty"`
	Payload              map[string]interface{} `json:"-"`
}

type codexHookResponse struct {
	Action            string                 `json:"action"`
	RawAction         string                 `json:"raw_action,omitempty"`
	Severity          string                 `json:"severity"`
	Reason            string                 `json:"reason,omitempty"`
	Findings          []string               `json:"findings,omitempty"`
	Mode              string                 `json:"mode"`
	WouldBlock        bool                   `json:"would_block"`
	AdditionalContext string                 `json:"additional_context,omitempty"`
	CodexOutput       map[string]interface{} `json:"codex_output,omitempty"`
	// EvaluationID + RuleIDs join this hook response to the
	// matching scan_findings rows / audit row. Additive — older
	// connector hook scripts ignore the fields.
	EvaluationID string   `json:"evaluation_id,omitempty"`
	RuleIDs      []string `json:"rule_ids,omitempty"`
	// RedactionEnabled carries the cloud-controlled per-inspection
	// redaction directive back through the unified dispatch so
	// finalizeAgentHook can honor it on the hook_decision event +
	// audit row. Never serialized on the hook response wire.
	RedactionEnabled *bool  `json:"-"`
	SourceReason     string `json:"-"`
}

// handleCodexHook + enrichCodexHookContext were deleted in the
// unified hook collector refactor. Codex hook traffic now flows
// through the unified pipeline at handleAgentHook("codex"); the
// typed evaluator (evaluateCodexHook, kept below) is invoked through
// the HookProfile runtime registry. Codex-specific span enrichment
// (turn_id, gen_ai.tool.call.id, model) is preserved by the runtime
// callback immediately before evaluateCodexHook runs.
//
// The unified pipeline owns shared concerns (audit envelope refresh,
// dispatch metric, dedup, trace propagation, v8 observability emissions) in
// exactly one place now. See agent_hook.go and hook_profile_runtime.go
// for the registry and shared-pipeline rationale. The evaluator
// stamps the unified-pipeline correlation keys (resp.EvaluationID /
// resp.RuleIDs) on its return value so downstream tooling and the
// audit envelope receive them.

func enrichCodexHookSpan(ctx context.Context, req codexHookRequest) {
	span := trace.SpanFromContext(ctx)
	if span == nil || !span.IsRecording() {
		return
	}
	if req.SessionID != "" {
		span.SetAttributes(attribute.String("gen_ai.conversation.id", req.SessionID))
	}
	agentName := strings.TrimSpace(req.AgentType)
	if agentName == "" {
		agentName = "codex"
	}
	span.SetAttributes(attribute.String("gen_ai.agent.name", agentName))
	span.SetAttributes(attribute.String("gen_ai.agent.type", agentName))
	if req.AgentID != "" {
		span.SetAttributes(attribute.String("gen_ai.agent.id", req.AgentID))
	}
	if req.HookEventName != "" {
		span.SetAttributes(attribute.String("defenseclaw.codex.hook.event", req.HookEventName))
	}
	if req.TurnID != "" {
		span.SetAttributes(
			attribute.String("defenseclaw.turn_id", req.TurnID),
			attribute.String("defenseclaw.codex.hook.turn_id", req.TurnID),
		)
	}
	if req.Model != "" {
		span.SetAttributes(attribute.String("gen_ai.request.model", req.Model))
	}
	if req.ToolName != "" {
		span.SetAttributes(attribute.String("gen_ai.tool.name", req.ToolName))
	}
	if req.ToolUseID != "" {
		span.SetAttributes(attribute.String("gen_ai.tool.call.id", req.ToolUseID))
	}
}

func (a *APIServer) evaluateCodexHook(ctx context.Context, req codexHookRequest) codexHookResponse {
	mode := a.codexMode()
	if a.scannerCfg != nil && !a.codexEnabled() {
		return codexResponseFor(req.HookEventName, "allow", "allow", "NONE", "", nil, mode, false)
	}
	t0 := time.Now()

	verdict := &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	var assetDecisions []runtimeAssetDecision
	switch req.HookEventName {
	case "SessionStart":
		if req.ScanComponents || (a.scannerCfg != nil && a.scannerCfg.ConnectorHookConfig("codex").ScanOnSessionStart) {
			count := a.scanCodexComponents(ctx, req)
			if count > 0 {
				verdict = &ToolInspectVerdict{
					Action:   "allow",
					Severity: "INFO",
					Reason:   fmt.Sprintf("scanned %d Codex component(s)", count),
					Findings: []string{"CODEX-COMPONENT-SCAN"},
				}
			}
		}
	case "UserPromptSubmit":
		verdict = a.inspectMessageContent(ctx, &ToolInspectRequest{
			Tool:         "message",
			Content:      req.Prompt,
			Direction:    "prompt",
			Connector:    "codex",
			contentScope: ruleContentScopeUntrusted,
		})
		if decision, matched := a.codexPromptSkillAssetDecision(ctx, req); matched {
			assetDecisions = append(assetDecisions, runtimeAssetDecision{
				targetType: "skill",
				decision:   decision,
			})
		}
	case "PreToolUse", "PermissionRequest":
		toolName := codexToolName(req)
		toolArgs := codexToolArgs(req)
		toolRequest := &ToolInspectRequest{
			Tool:          toolName,
			Args:          toolArgs,
			Direction:     "tool_call",
			Connector:     "codex",
			MCPServerName: firstNonEmpty(req.MCPServerName, payloadString(req.Payload, "mcp_server_name")),
		}
		verdict = a.inspectTrustedToolPolicyCtx(ctx, toolRequest, trustedActionRequest{
			Input: actionfacts.Input{
				Tool:       toolName,
				Args:       toolArgs,
				CWD:        req.CWD,
				ActiveHome: trustedSameHostHome(),
			},
			LegacyText:         string(toolArgs),
			Connector:          "codex",
			EnforcementCapable: true,
			repositoryPolicy: a.repositoryPolicyProofForTrustedHookCWD(
				ctx,
				"codex",
				req.CWD,
			),
			DowngradeReadOnlyDataArgs: mode != "action",
			record:                    toolChainRecorderFromContext(ctx),
		})
		if decision, matched := a.codexMCPAssetDecision(ctx, req); matched {
			assetDecisions = append(assetDecisions, runtimeAssetDecision{targetType: "mcp", decision: decision})
		}
		if decision, matched := a.codexSkillAssetDecision(ctx, req); matched {
			assetDecisions = append(assetDecisions, runtimeAssetDecision{targetType: "skill", decision: decision})
		}
	case "PostToolUse":
		verdict = a.inspectCodexToolResult(ctx, req, mode)
		if decision, matched := a.codexMCPAssetDecision(ctx, req); matched {
			assetDecisions = append(assetDecisions, runtimeAssetDecision{targetType: "mcp", decision: decision})
		}
		if decision, matched := a.codexSkillAssetDecision(ctx, req); matched {
			assetDecisions = append(assetDecisions, runtimeAssetDecision{targetType: "skill", decision: decision})
		}
	case "Stop":
		if !req.StopHookActive && a.scannerCfg != nil && a.scannerCfg.ConnectorHookConfig("codex").ScanOnStop {
			verdict = a.scanCodexChangedFiles(ctx, req)
		}
	}

	// Inject the cloud-controlled per-inspection redaction directive
	// onto the context so the downstream emit choke points (findings,
	// verdict/hook_decision events) and the OS toast honor it. No-op
	// outside managed_enterprise / when the AID lane returned no
	// directive.
	ctx = withRedactionDecision(ctx, verdict.RedactionEnabled)

	rawAction := normalizeCodexAction(verdict.Action)
	rawActionBeforeAssets := rawAction
	action := rawAction
	wouldBlock := rawAction == "block" && mode != "action"
	if mode != "action" && rawAction == "block" {
		action = "allow"
	}
	if mode != "action" && (rawAction == "alert" || rawAction == "confirm") {
		action = "allow"
	}
	if mode == "action" && rawAction == "confirm" {
		action = "alert"
	}
	assetContextEligible := false
	for _, asset := range assetDecisions {
		mergedAction, mergedRawAction, mergedSeverity, mergedReason, mergedFindings, assetWouldBlock := mergeAssetDecision(
			asset.decision, true, asset.targetType, req.HookEventName, action, rawAction, verdict.Severity, verdict.Reason, verdict.Findings,
		)
		action = mergedAction
		rawAction = mergedRawAction
		verdict.Severity = mergedSeverity
		verdict.Reason = mergedReason
		verdict.Findings = mergedFindings
		if assetWouldBlock {
			wouldBlock = true
		}
		if asset.decision.RawAction == "block" {
			assetContextEligible = true
		}
	}
	// Emit per-rule findings FIRST so the notification + audit
	// rows produced below can carry the resulting evaluation_id
	// and top rule_ids — keeping the SIEM pivot key identical
	// across canonical logs, OS notification, and the
	// HTTP response body.
	evalCtx := a.emitHookRuleFindings(ctx, "codex", req.HookEventName, verdict,
		hookTargetTypeForEvent(req.HookEventName), time.Since(t0))
	if !hookNotificationCoveredByAssetPolicy(rawActionBeforeAssets, assetDecisions) {
		a.dispatchCodexHookNotification(req, action, rawAction, verdict.Severity, verdict.Reason, wouldBlock, evalCtx,
			sinkPolicyFor(ctx, verdict.RedactionEnabled))
	}
	resp := codexResponseFor(
		req.HookEventName, action, rawAction, verdict.Severity, verdict.Reason, verdict.Findings, mode, wouldBlock,
		sinkPolicyFor(ctx, verdict.RedactionEnabled),
	)
	if mode != "action" && resp.AdditionalContext != "" {
		eligible := assetContextEligible || codexObserveContextEnforcementEligible(verdict)
		if !eligible || !a.codexAdditionalContextFirstInWindow(req, rawAction, verdict, time.Now()) {
			clearCodexAdditionalContext(&resp, req.HookEventName)
		}
	}
	resp.EvaluationID = evalCtx.EvaluationID
	resp.RuleIDs = evalCtx.RuleIDs
	resp.RedactionEnabled = verdict.RedactionEnabled
	return resp
}

// dispatchCodexHookNotification mirrors the Claude Code path —
// see dispatchClaudeCodeHookNotification for the routing contract,
// including the redaction.ForSinkReason scrub on the reason string.
// dispatchCodexHookNotification follows the same routing contract
// documented on dispatchAgentHookNotification. See that comment for
// the rationale behind WouldAsk routing through OnWouldBlock.
func (a *APIServer) dispatchCodexHookNotification(req codexHookRequest, action, rawAction, severity, reason string, wouldBlock bool, evalCtx hookEvaluationContext, policy ...redaction.SinkPolicy) {
	if a == nil || a.notifier == nil {
		return
	}
	target := strings.TrimSpace(req.ToolName)
	if target == "" {
		target = req.HookEventName
	}
	// Honor the cloud-controlled per-inspection redaction policy
	// (all-sinks scope, managed_enterprise only) when a caller passes
	// one; otherwise keep compatibility redaction while allowing exact
	// compiled-in rule metadata through for operator triage.
	safeReason := notificationDisplayReason(reason, notificationSinkPolicy(policy))
	base := notifier.BlockEvent{
		Source:       notifier.SourceHook,
		Target:       target,
		Reason:       safeReason,
		Severity:     severity,
		Connector:    "codex",
		Event:        req.HookEventName,
		EvaluationID: evalCtx.EvaluationID,
		RuleIDs:      evalCtx.RuleIDs,
	}
	switch {
	case action == "block":
		a.notifier.OnBlock(base)
	case rawAction == "block" && (wouldBlock || action != "block"):
		a.notifier.OnWouldBlock(base)
	case action == "confirm":
		a.notifier.OnApprovalPending(notifier.ApprovalEvent{
			Subject:      fmt.Sprintf("%s (%s)", target, req.HookEventName),
			Reason:       safeReason,
			Severity:     severity,
			Source:       notifier.SourceHook,
			Connector:    "codex",
			Event:        req.HookEventName,
			EvaluationID: evalCtx.EvaluationID,
			RuleIDs:      evalCtx.RuleIDs,
		})
	case rawAction == "confirm":
		evt := base
		evt.WouldAsk = true
		a.notifier.OnWouldBlock(evt)
	}
}

// codexEnabled mirrors claudeCodeEnabled: selecting the codex connector
// is a sufficient opt-in — the connector's Setup() has already written
// the codex-hook.sh script and (on Codex's side) registered it. An
// explicit codex.enabled flag still wins for operators running codex
// alongside a different selected connector.
func (a *APIServer) codexEnabled() bool {
	cfg := a.runtimeConfigSnapshot()
	if cfg == nil {
		return false
	}
	// Per-connector explicit disable wins over every enable signal below:
	// an operator who ran `guardrail disable --connector codex` gets
	// allow-without-scan even though codex is still a member of
	// guardrail.connectors (its policy is retained for re-enable).
	// Defense-in-depth — the boot loop already tears codex's hooks down,
	// so this only matters in the window before a restart or if a hook
	// still calls in. EffectiveEnabled defaults to true, so this is a
	// no-op for single-connector installs and any connector never
	// explicitly disabled.
	if cfg.ManualConnectorConfigured("codex") && !cfg.Guardrail.EffectiveEnabled("codex") {
		return false
	}
	if cfg.ConnectorHookConfig("codex").Enabled {
		return true
	}
	if a.health != nil && a.health.HasConnectorSource("codex", "automatic") && cfg.ApplicationProtection.EffectiveEnabled("codex") {
		return true
	}
	// Multi-connector: membership in guardrail.connectors opts codex in
	// even when it is not the singular primary (no-op for single).
	if cfg.Guardrail.HasConnector("codex") {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(cfg.Guardrail.Connector), "codex")
}

func (a *APIServer) codexMode() string {
	mode := "observe"
	if cfg := a.runtimeConfigSnapshot(); cfg != nil {
		mode = strings.TrimSpace(cfg.ConnectorHookConfig("codex").Mode)
		if mode == "" || mode == "inherit" {
			// Per-connector guardrail override wins over global mode.
			mode = strings.TrimSpace(cfg.EffectiveGuardrailModeForConnector("codex"))
		}
	}
	return normalizeAgentHookMode(mode)
}

func codexResponseFor(event, action, rawAction, severity, reason string, findings []string, mode string, wouldBlock bool, policy ...redaction.SinkPolicy) codexHookResponse {
	if severity == "" {
		severity = "NONE"
	}
	if action == "" {
		action = "allow"
	}
	if rawAction == "" {
		rawAction = action
	}
	safeReason := agentDisplayReason(reason, notificationSinkPolicy(policy))
	additional := codexAdditionalContext(rawAction, severity, safeReason, mode, wouldBlock)
	resp := codexHookResponse{
		Action:            action,
		RawAction:         rawAction,
		Severity:          severity,
		Reason:            safeReason,
		Findings:          findings,
		Mode:              mode,
		WouldBlock:        wouldBlock,
		AdditionalContext: additional,
		SourceReason:      reason,
	}
	outputRawAction := rawAction
	if mode != "action" && additional == "" {
		// Preserve RawAction in the response/audit contract, but do not let
		// codexOutput's Action-mode confirmation fallback recreate a warning
		// that Observe-mode severity gating intentionally suppressed.
		outputRawAction = action
	}
	resp.CodexOutput = codexOutput(event, action, outputRawAction, safeReason, additional)
	return resp
}

func codexOutput(event, action, rawAction, reason, additional string) map[string]interface{} {
	if action == "block" {
		switch event {
		case "PreToolUse":
			return map[string]interface{}{
				"hookSpecificOutput": map[string]interface{}{
					"hookEventName":            "PreToolUse",
					"permissionDecision":       "deny",
					"permissionDecisionReason": reasonOrDefault(reason),
				},
			}
		case "PermissionRequest":
			return map[string]interface{}{
				"hookSpecificOutput": map[string]interface{}{
					"hookEventName": "PermissionRequest",
					"decision": map[string]interface{}{
						"behavior": "deny",
						"message":  reasonOrDefault(reason),
					},
				},
			}
		case "UserPromptSubmit", "PostToolUse", "Stop":
			out := map[string]interface{}{
				"decision": "block",
				"reason":   reasonOrDefault(reason),
			}
			if event == "PostToolUse" && additional != "" {
				out["hookSpecificOutput"] = map[string]interface{}{
					"hookEventName":     "PostToolUse",
					"additionalContext": additional,
				}
			}
			return out
		}
	}

	if rawAction == "confirm" {
		if additional == "" {
			additional = "DefenseClaw wants user confirmation for this action."
		}
		switch event {
		case "PermissionRequest", "PreToolUse":
			return map[string]interface{}{"systemMessage": additional}
		}
	}

	if event == "Stop" {
		return map[string]interface{}{"continue": true}
	}
	if additional == "" {
		return nil
	}
	switch event {
	case "SessionStart":
		return map[string]interface{}{"systemMessage": additional}
	case "UserPromptSubmit", "PostToolUse":
		return map[string]interface{}{
			"hookSpecificOutput": map[string]interface{}{
				"hookEventName":     event,
				"additionalContext": additional,
			},
		}
	case "PreToolUse":
		return map[string]interface{}{"systemMessage": additional}
	default:
		return nil
	}
}

func codexAdditionalContext(rawAction, severity, reason, mode string, wouldBlock bool) string {
	if rawAction == "allow" || rawAction == "" {
		return ""
	}
	if mode != "action" && guardrailSeverityRank(severity) < severityHigh {
		return ""
	}
	prefix := "DefenseClaw observed"
	if wouldBlock {
		prefix = "DefenseClaw would block this in action mode"
	}
	if reason == "" {
		return fmt.Sprintf("%s a %s Codex hook finding.", prefix, severity)
	}
	return fmt.Sprintf("%s a %s Codex hook finding: %s", prefix, severity, reason)
}

// codexObserveContextEnforcementEligible keeps the in-chat Observe warning
// coupled to a finding that could actually influence enforcement. Opaque
// managed/judge verdicts may not carry DetailedFindings, so a HIGH/CRITICAL
// non-allow verdict with no details remains visible; explicit detection-only
// details do not.
func codexObserveContextEnforcementEligible(verdict *ToolInspectVerdict) bool {
	if verdict == nil || guardrailSeverityRank(verdict.Severity) < severityHigh {
		return false
	}
	if len(verdict.DetailedFindings) == 0 {
		return true
	}
	for _, finding := range verdict.DetailedFindings {
		if finding.contributesToEnforcement() &&
			guardrailSeverityRank(finding.Severity) >= severityHigh {
			return true
		}
	}
	return false
}

type codexAdditionalContextFindingKey struct {
	RuleID      string
	Title       string
	Severity    string
	Evidence    string
	Enforcement findingEnforcement
}

// codexAdditionalContextFirstInWindow returns false only for an identical
// advisory message in the same Codex session and presentation lifecycle.
// PermissionRequest and PreToolUse are one pre-action presentation family so
// Codex's paired callbacks cannot repeat the same warning; canonical audit and
// notification emission still occurs before this cache for both events. Raw
// evidence is included in the transient digest input so two real values remain
// distinct, but the cache stores only the SHA-256 key and timestamps.
func (a *APIServer) codexAdditionalContextFirstInWindow(
	req codexHookRequest,
	rawAction string,
	verdict *ToolInspectVerdict,
	now time.Time,
) bool {
	if a == nil || verdict == nil || strings.TrimSpace(req.SessionID) == "" {
		return true
	}
	findings := append([]string(nil), verdict.Findings...)
	sort.Strings(findings)
	details := make([]codexAdditionalContextFindingKey, 0, len(verdict.DetailedFindings))
	for _, finding := range verdict.DetailedFindings {
		details = append(details, codexAdditionalContextFindingKey{
			RuleID:      finding.RuleID,
			Title:       finding.Title,
			Severity:    finding.Severity,
			Evidence:    finding.Evidence,
			Enforcement: finding.enforcement,
		})
	}
	sort.Slice(details, func(i, j int) bool {
		left, _ := json.Marshal(details[i])
		right, _ := json.Marshal(details[j])
		return bytes.Compare(left, right) < 0
	})
	digestInput, _ := json.Marshal(struct {
		SessionID string
		Event     string
		RawAction string
		Severity  string
		Reason    string
		Findings  []string
		Details   []codexAdditionalContextFindingKey
	}{
		SessionID: req.SessionID,
		Event:     codexAdditionalContextEventFamily(req.HookEventName),
		RawAction: rawAction,
		Severity:  verdict.Severity,
		Reason:    verdict.Reason,
		Findings:  findings,
		Details:   details,
	})
	key := sha256.Sum256(digestInput)

	a.codexAdditionalContextMu.Lock()
	defer a.codexAdditionalContextMu.Unlock()
	if a.codexAdditionalContextSeen == nil {
		a.codexAdditionalContextSeen = make(map[[sha256.Size]byte]time.Time)
	}
	cut := 0
	for cut < len(a.codexAdditionalContextOrder) {
		entry := a.codexAdditionalContextOrder[cut]
		if now.Sub(entry.seen) < codexAdditionalContextDedupWindow {
			break
		}
		if seen, ok := a.codexAdditionalContextSeen[entry.key]; ok && seen.Equal(entry.seen) {
			delete(a.codexAdditionalContextSeen, entry.key)
		}
		cut++
	}
	if cut > 0 {
		copy(a.codexAdditionalContextOrder, a.codexAdditionalContextOrder[cut:])
		a.codexAdditionalContextOrder = a.codexAdditionalContextOrder[:len(a.codexAdditionalContextOrder)-cut]
	}
	if seen, ok := a.codexAdditionalContextSeen[key]; ok &&
		now.Sub(seen) < codexAdditionalContextDedupWindow {
		return false
	}
	for len(a.codexAdditionalContextSeen) >= codexAdditionalContextDedupMaxEntries &&
		len(a.codexAdditionalContextOrder) > 0 {
		oldest := a.codexAdditionalContextOrder[0]
		a.codexAdditionalContextOrder = a.codexAdditionalContextOrder[1:]
		if seen, ok := a.codexAdditionalContextSeen[oldest.key]; ok && seen.Equal(oldest.seen) {
			delete(a.codexAdditionalContextSeen, oldest.key)
		}
	}
	a.codexAdditionalContextSeen[key] = now
	a.codexAdditionalContextOrder = append(a.codexAdditionalContextOrder, codexAdditionalContextEntry{
		key: key, seen: now,
	})
	return true
}

func codexAdditionalContextEventFamily(event string) string {
	switch event {
	case "PreToolUse", "PermissionRequest":
		return "pre_action"
	default:
		return event
	}
}

func clearCodexAdditionalContext(resp *codexHookResponse, event string) {
	if resp == nil {
		return
	}
	resp.AdditionalContext = ""
	outputRawAction := resp.RawAction
	if resp.Mode != "action" {
		outputRawAction = resp.Action
	}
	resp.CodexOutput = codexOutput(
		event, resp.Action, outputRawAction, resp.Reason, "",
	)
}

func reasonOrDefault(reason string) string {
	if strings.TrimSpace(reason) == "" {
		return "Blocked by DefenseClaw Codex policy."
	}
	return reason
}

func normalizeCodexAction(action string) string {
	return normalizedGuardrailAction(action)
}

func codexToolName(req codexHookRequest) string {
	if strings.TrimSpace(req.ToolName) != "" {
		return req.ToolName
	}
	return "Bash"
}

func codexToolArgs(req codexHookRequest) json.RawMessage {
	if req.ToolInput == nil {
		return json.RawMessage(`{}`)
	}
	b, err := json.Marshal(req.ToolInput)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}

func codexToolResponseString(v interface{}) string {
	return structuredHookContentString(v)
}

// structuredHookContentString keeps the original JSON representation for
// detectors that need key/value context, and also projects bounded string
// leaves onto their own lines. The latter gives contextual injection rules a
// real content boundary instead of hiding stdout behind `{"stdout":"..."}`.
func structuredHookContentString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return ""
		}
		var decoded interface{}
		if err := json.Unmarshal(b, &decoded); err != nil {
			return string(b)
		}
		leaves := make([]string, 0, 8)
		collectHookContentStrings(decoded, &leaves, 0)
		if len(leaves) == 0 {
			return string(b)
		}
		leaves = append(leaves, string(b))
		return strings.Join(leaves, "\n")
	}
}

// collectHookContentStrings returns false when its traversal bounds prevent it
// from examining the complete value. Ordinary detector projections may still
// use the collected prefix, but source-provenance callers must fail closed.
func collectHookContentStrings(v interface{}, leaves *[]string, depth int) bool {
	const (
		maxDepth  = 8
		maxLeaves = 256
	)
	if depth > maxDepth {
		return false
	}
	switch value := v.(type) {
	case string:
		if strings.TrimSpace(value) != "" {
			if len(*leaves) >= maxLeaves {
				return false
			}
			*leaves = append(*leaves, value)
		}
	case []interface{}:
		for _, item := range value {
			if !collectHookContentStrings(item, leaves, depth+1) {
				return false
			}
		}
	case map[string]interface{}:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if !collectHookContentStrings(value[key], leaves, depth+1) {
				return false
			}
		}
	}
	return true
}

type codexObserveSourceProof uint8

const (
	codexObserveSourceUntrusted codexObserveSourceProof = iota
	codexObserveSourceComplete
	// A porcelain git-status segment followed by attributed source-search
	// output has mixed provenance. Only physically attributed source lines are
	// downgraded; status/process lines keep the untrusted detector boundary.
	codexObserveSourceMixedStatus
	// A statically proven working-tree git diff still has mixed provenance:
	// only added/context hunk lines that match the physically validated current
	// file may enter source scope. Diff metadata, removed lines, malformed
	// hunks, and sibling process output remain untrusted.
	codexObserveSourceVerifiedDiff
)

func (a *APIServer) inspectCodexToolResult(
	ctx context.Context,
	req codexHookRequest,
	mode string,
) *ToolInspectVerdict {
	content := codexToolResponseString(req.ToolResponse)
	strictScope := codexToolResultContentScope(req)
	if mode == "action" || strictScope == ruleContentScopeSource {
		return a.inspectMessageContent(ctx, codexToolResultInspectRequest(content, strictScope))
	}

	proof := codexObserveWorkspaceSourceProofForRequest(req)
	switch proof {
	case codexObserveSourceComplete:
		return a.inspectMessageContent(ctx, codexToolResultInspectRequest(content, ruleContentScopeSource))
	case codexObserveSourceMixedStatus:
		source, untrusted, ok := codexSplitAttributedSourceResult(req.ToolResponse, req.CWD)
		return a.inspectCodexSegmentedToolResult(ctx, content, source, untrusted, ok)
	case codexObserveSourceVerifiedDiff:
		pathspecs, ok := codexObserveGitDiffPathspecsForRequest(req)
		if !ok {
			return a.inspectMessageContent(
				ctx, codexToolResultInspectRequest(content, ruleContentScopeUntrusted),
			)
		}
		source, untrusted, ok := codexSplitVerifiedGitDiffResult(
			req.ToolResponse, req.CWD, pathspecs,
		)
		return a.inspectCodexSegmentedToolResult(ctx, content, source, untrusted, ok)
	default:
		return a.inspectMessageContent(ctx, codexToolResultInspectRequest(content, ruleContentScopeUntrusted))
	}
}

func (a *APIServer) inspectCodexSegmentedToolResult(
	ctx context.Context,
	fallback, source, untrusted string,
	ok bool,
) *ToolInspectVerdict {
	if !ok {
		return a.inspectMessageContent(
			ctx, codexToolResultInspectRequest(fallback, ruleContentScopeUntrusted),
		)
	}
	var sourceVerdict, untrustedVerdict *ToolInspectVerdict
	if source != "" {
		sourceVerdict = a.inspectMessageContent(
			ctx, codexToolResultInspectRequest(source, ruleContentScopeSource),
		)
	}
	if untrusted != "" {
		untrustedVerdict = a.inspectMessageContent(
			ctx, codexToolResultInspectRequest(untrusted, ruleContentScopeUntrusted),
		)
	}
	return mergeCodexToolResultVerdicts(sourceVerdict, untrustedVerdict)
}

func codexToolResultInspectRequest(content string, scope ruleContentScope) *ToolInspectRequest {
	return &ToolInspectRequest{
		Tool:         "message",
		Content:      content,
		Direction:    "tool_result",
		Connector:    "codex",
		contentScope: scope,
	}
}

func mergeCodexToolResultVerdicts(
	source, untrusted *ToolInspectVerdict,
) *ToolInspectVerdict {
	if source == nil {
		if untrusted != nil {
			return untrusted
		}
		return &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	}
	if untrusted == nil {
		return source
	}

	merged := *source
	merged.Findings = append(append([]string(nil), source.Findings...), untrusted.Findings...)
	merged.DetailedFindings = append(
		append([]RuleFinding(nil), source.DetailedFindings...),
		untrusted.DetailedFindings...,
	)
	if guardrailSeverityRank(untrusted.Severity) > guardrailSeverityRank(source.Severity) {
		merged.Severity = untrusted.Severity
		merged.Confidence = untrusted.Confidence
		merged.Reason = untrusted.Reason
	} else if untrusted.Confidence > merged.Confidence {
		merged.Confidence = untrusted.Confidence
	}
	if normalizedGuardrailActionRank(untrusted.Action) > normalizedGuardrailActionRank(source.Action) {
		merged.Action = untrusted.Action
	}
	if untrusted.RawAction != "" && (source.RawAction == "" ||
		normalizedGuardrailActionRank(untrusted.RawAction) >
			normalizedGuardrailActionRank(source.RawAction)) {
		merged.RawAction = untrusted.RawAction
	}
	merged.WouldBlock = source.WouldBlock || untrusted.WouldBlock
	if source.RedactionEnabled != nil || untrusted.RedactionEnabled != nil {
		enabled := source.RedactionEnabled != nil && *source.RedactionEnabled ||
			untrusted.RedactionEnabled != nil && *untrusted.RedactionEnabled
		merged.RedactionEnabled = &enabled
	}
	return &merged
}

func normalizedGuardrailActionRank(action string) int {
	switch normalizeCodexAction(action) {
	case "block":
		return 3
	case "confirm":
		return 2
	case "alert":
		return 1
	default:
		return 0
	}
}

// codexSplitAttributedSourceResult separates the only mixed-provenance shape
// accepted in Observe mode: short/porcelain git status followed by rg/grep
// output that carries a physical workspace path and line number. Any line
// without that proof—including a hostile filename printed by git status—stays
// untrusted. Structured hook envelopes contribute their string leaves only;
// the JSON projection would otherwise duplicate a whole stdout leaf and erase
// the per-line boundary.
func codexSplitAttributedSourceResult(v interface{}, cwd string) (string, string, bool) {
	var leaves []string
	switch typed := v.(type) {
	case string:
		leaves = []string{typed}
	case nil:
		return "", "", false
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return "", "", false
		}
		var decoded interface{}
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			return "", "", false
		}
		if !collectHookContentStrings(decoded, &leaves, 0) {
			return "", "", false
		}
	}
	if len(leaves) == 0 {
		return "", "", false
	}
	trust := newCodexAttributedSourceTrust(cwd)
	var sourceLines, untrustedLines []string
	for _, leaf := range leaves {
		for _, line := range strings.Split(strings.ReplaceAll(leaf, "\r\n", "\n"), "\n") {
			if codexAttributedWorkspaceSourceLine(line, trust) {
				sourceLines = append(sourceLines, line)
			} else if line != "" {
				untrustedLines = append(untrustedLines, line)
			}
		}
	}
	if len(sourceLines) == 0 {
		return "", strings.Join(untrustedLines, "\n"), false
	}
	return strings.Join(sourceLines, "\n"), strings.Join(untrustedLines, "\n"), true
}

const (
	codexAttributedSourceMaxCandidatesPerLine = 32
	codexAttributedSourceMaxMemoEntries       = 256
)

type codexAttributedSourceTrust struct {
	cwd      string
	paths    map[string]bool
	validate func(path, cwd string) bool
}

func newCodexAttributedSourceTrust(cwd string) *codexAttributedSourceTrust {
	return &codexAttributedSourceTrust{
		cwd:      cwd,
		paths:    make(map[string]bool),
		validate: trustedCodexObserveSourcePath,
	}
}

func (t *codexAttributedSourceTrust) trusted(relative, path string) bool {
	if t == nil || t.validate == nil {
		return false
	}
	key := filepath.Clean(relative)
	if trusted, cached := t.paths[key]; cached {
		return trusted
	}
	// An attacker-controlled result cannot force unbounded distinct filesystem
	// proofs. Once the request-local cache is full, unseen paths remain untrusted.
	if len(t.paths) >= codexAttributedSourceMaxMemoEntries {
		return false
	}
	trusted := t.validate(path, t.cwd)
	t.paths[key] = trusted
	return trusted
}

func codexAttributedWorkspaceSourceLine(
	line string,
	trust *codexAttributedSourceTrust,
) bool {
	if trust == nil {
		return false
	}
	line = strings.TrimSuffix(line, "\r")
	candidates := 0
	for index := 0; index < len(line); index++ {
		separator := line[index]
		if separator != ':' && separator != '-' {
			continue
		}
		digits := index + 1
		end := digits
		for end < len(line) && line[end] >= '0' && line[end] <= '9' {
			end++
		}
		if end == digits || end >= len(line) || line[end] != separator {
			continue
		}
		path := line[:index]
		relative, ok := trustedWorkspaceRelativePath(path, trust.cwd)
		if !ok || !codexObserveSourceRelativePath(relative) {
			continue
		}
		candidates++
		if candidates > codexAttributedSourceMaxCandidatesPerLine {
			return false
		}
		if trust.trusted(relative, path) {
			return true
		}
	}
	return false
}

type codexObserveGitDiffPathspec struct {
	relative  string
	directory bool
}

// codexSplitVerifiedGitDiffResult treats a git diff as a segmented result,
// never as one trusted blob. A content line enters source scope only when a
// complete unified-diff hunk maps it to the exact current line of a physically
// validated workspace source file covered by an explicit command pathspec.
// Everything else—including git status text and arbitrary sibling output—is
// returned through the untrusted lane.
func codexSplitVerifiedGitDiffResult(
	v interface{},
	cwd string,
	pathspecs []codexObserveGitDiffPathspec,
) (string, string, bool) {
	var leaves []string
	switch typed := v.(type) {
	case string:
		leaves = []string{typed}
	case nil:
		return "", "", false
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return "", "", false
		}
		var decoded interface{}
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			return "", "", false
		}
		if !collectHookContentStrings(decoded, &leaves, 0) {
			return "", "", false
		}
	}
	if len(leaves) == 0 || len(pathspecs) == 0 {
		return "", "", false
	}

	var sourceLines, untrustedLines []string
	verified := false
	for _, leaf := range leaves {
		source, untrusted, leafVerified := codexSplitVerifiedGitDiffText(
			leaf, cwd, pathspecs,
		)
		if source != "" {
			sourceLines = append(sourceLines, source)
		}
		if untrusted != "" {
			untrustedLines = append(untrustedLines, untrusted)
		}
		verified = verified || leafVerified
	}
	return strings.Join(sourceLines, "\n"), strings.Join(untrustedLines, "\n"), verified
}

func codexSplitVerifiedGitDiffText(
	text string,
	cwd string,
	pathspecs []codexObserveGitDiffPathspec,
) (string, string, bool) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var sourceLines, untrustedLines []string
	verified := false
	for index := 0; index < len(lines); {
		if !strings.HasPrefix(lines[index], "diff --git ") {
			if lines[index] != "" {
				untrustedLines = append(untrustedLines, lines[index])
			}
			index++
			continue
		}

		end := index + 1
		for end < len(lines) && !strings.HasPrefix(lines[end], "diff --git ") {
			end++
		}
		block := lines[index:end]
		trusted, ok := codexVerifiedGitDiffBlockLines(block, cwd, pathspecs)
		if !ok {
			for _, line := range block {
				if line != "" {
					untrustedLines = append(untrustedLines, line)
				}
			}
			index = end
			continue
		}
		for blockIndex, line := range block {
			if content, ok := trusted[blockIndex]; ok {
				sourceLines = append(sourceLines, content)
				verified = true
			} else if line != "" {
				untrustedLines = append(untrustedLines, line)
			}
		}
		index = end
	}
	return strings.Join(sourceLines, "\n"), strings.Join(untrustedLines, "\n"), verified
}

func codexVerifiedGitDiffBlockLines(
	block []string,
	cwd string,
	pathspecs []codexObserveGitDiffPathspec,
) (map[int]string, bool) {
	if len(block) == 0 || !strings.HasPrefix(block[0], "diff --git a/") {
		return nil, false
	}

	oldHeader := -1
	newHeader := -1
	firstHunk := -1
	for index := 1; index < len(block); index++ {
		line := block[index]
		if strings.HasPrefix(line, "@@ ") {
			firstHunk = index
			break
		}
		if strings.HasPrefix(line, "--- ") {
			if oldHeader >= 0 || index+1 >= len(block) ||
				!strings.HasPrefix(block[index+1], "+++ ") {
				return nil, false
			}
			oldHeader = index
			newHeader = index + 1
			index++
			continue
		}
		if strings.HasPrefix(line, "+++ ") {
			return nil, false
		}
	}
	if firstHunk < 0 {
		// Binary and metadata-only diffs have no source-content lines. They
		// remain wholly untrusted instead of manufacturing source provenance.
		return map[int]string{}, true
	}
	if oldHeader < 0 || newHeader < 0 || newHeader >= firstHunk {
		return nil, false
	}

	oldPath := strings.TrimPrefix(block[oldHeader], "--- ")
	newPath := strings.TrimPrefix(block[newHeader], "+++ ")
	if strings.ContainsAny(oldPath, "\t\x00") || strings.ContainsAny(newPath, "\t\x00") ||
		(oldPath != "/dev/null" && !strings.HasPrefix(oldPath, "a/")) ||
		!strings.HasPrefix(newPath, "b/") {
		return nil, false
	}
	relative := strings.TrimPrefix(newPath, "b/")
	if relative == "" || strings.HasPrefix(relative, `"`) || strings.HasSuffix(relative, `"`) ||
		!strings.HasSuffix(block[0], " b/"+relative) {
		return nil, false
	}
	currentLines, ok := codexReadVerifiedGitDiffCurrentLines(relative, cwd, pathspecs)
	if !ok {
		return nil, false
	}

	trusted := make(map[int]string)
	activeHunk := false
	oldRemaining := 0
	newRemaining := 0
	newLine := 0
	for index := firstHunk; index < len(block); index++ {
		line := block[index]
		if strings.HasPrefix(line, "@@ ") {
			if activeHunk && (oldRemaining != 0 || newRemaining != 0) {
				return nil, false
			}
			_, oldCount, start, newCount, parsed := codexParseUnifiedDiffHunk(line)
			if !parsed {
				return nil, false
			}
			oldRemaining = oldCount
			newRemaining = newCount
			newLine = start
			activeHunk = oldRemaining != 0 || newRemaining != 0
			continue
		}
		if !activeHunk {
			if strings.HasPrefix(line, "--- ") || strings.HasPrefix(line, "+++ ") {
				return nil, false
			}
			continue
		}
		if line == `\ No newline at end of file` {
			continue
		}
		if line == "" {
			return nil, false
		}

		content := line[1:]
		switch line[0] {
		case ' ':
			if oldRemaining <= 0 || newRemaining <= 0 ||
				!codexGitDiffLineMatchesCurrent(currentLines, newLine, content) {
				return nil, false
			}
			trusted[index] = content
			oldRemaining--
			newRemaining--
			newLine++
		case '+':
			if newRemaining <= 0 ||
				!codexGitDiffLineMatchesCurrent(currentLines, newLine, content) {
				return nil, false
			}
			trusted[index] = content
			newRemaining--
			newLine++
		case '-':
			if oldRemaining <= 0 {
				return nil, false
			}
			// Removed bytes are deliberately never source-scoped, even if an
			// identical string happens to remain elsewhere in the current file.
			oldRemaining--
		default:
			return nil, false
		}
		if oldRemaining == 0 && newRemaining == 0 {
			activeHunk = false
		}
	}
	if activeHunk || oldRemaining != 0 || newRemaining != 0 {
		return nil, false
	}
	return trusted, true
}

func codexParseUnifiedDiffHunk(line string) (int, int, int, int, bool) {
	if !strings.HasPrefix(line, "@@ -") {
		return 0, 0, 0, 0, false
	}
	closeAt := strings.Index(line[3:], " @@")
	if closeAt < 0 {
		return 0, 0, 0, 0, false
	}
	fields := strings.Fields(line[3 : 3+closeAt])
	if len(fields) != 2 {
		return 0, 0, 0, 0, false
	}
	oldStart, oldCount, ok := codexParseUnifiedDiffRange(fields[0], '-')
	if !ok {
		return 0, 0, 0, 0, false
	}
	newStart, newCount, ok := codexParseUnifiedDiffRange(fields[1], '+')
	if !ok {
		return 0, 0, 0, 0, false
	}
	return oldStart, oldCount, newStart, newCount, true
}

func codexParseUnifiedDiffRange(value string, prefix byte) (int, int, bool) {
	if len(value) < 2 || value[0] != prefix {
		return 0, 0, false
	}
	startText, countText, hasCount := strings.Cut(value[1:], ",")
	start, err := strconv.Atoi(startText)
	if err != nil || start < 0 {
		return 0, 0, false
	}
	count := 1
	if hasCount {
		count, err = strconv.Atoi(countText)
		if err != nil || count < 0 {
			return 0, 0, false
		}
	}
	if count > 0 && start == 0 {
		return 0, 0, false
	}
	return start, count, true
}

func codexGitDiffLineMatchesCurrent(lines []string, lineNumber int, content string) bool {
	return lineNumber > 0 && lineNumber <= len(lines) && lines[lineNumber-1] == content
}

func codexReadVerifiedGitDiffCurrentLines(
	relative string,
	cwd string,
	pathspecs []codexObserveGitDiffPathspec,
) ([]string, bool) {
	physicalRelative, ok := trustedPhysicalWorkspaceRelativePath(filepath.FromSlash(relative), cwd)
	if !ok || !codexObserveSourceRelativePath(physicalRelative) ||
		!codexObserveGitDiffPathspecCovers(pathspecs, physicalRelative) {
		return nil, false
	}
	realCWD, err := filepath.EvalSymlinks(filepath.Clean(cwd))
	if err != nil || !filepath.IsAbs(realCWD) {
		return nil, false
	}
	target := filepath.Join(realCWD, physicalRelative)
	listed, err := os.Lstat(target)
	if err != nil || !listed.Mode().IsRegular() || listed.Size() < 0 ||
		listed.Size() > codexTrustedSourceTreeMaxBytes ||
		!codexSingleLinkRegularFile(target, listed) {
		return nil, false
	}
	file, err := os.Open(target)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(listed, opened) ||
		opened.Size() < 0 || opened.Size() > codexTrustedSourceTreeMaxBytes ||
		!codexSingleLinkRegularFile(target, opened) {
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(file, codexTrustedSourceTreeMaxBytes+1))
	if err != nil || int64(len(data)) > codexTrustedSourceTreeMaxBytes {
		return nil, false
	}
	final, err := file.Stat()
	if err != nil || !os.SameFile(opened, final) || final.Size() != int64(len(data)) ||
		!codexSingleLinkRegularFile(target, final) {
		return nil, false
	}
	content := strings.ReplaceAll(string(data), "\r\n", "\n")
	if content == "" {
		return []string{}, true
	}
	lines := strings.Split(content, "\n")
	if strings.HasSuffix(content, "\n") {
		lines = lines[:len(lines)-1]
	}
	return lines, true
}

func codexObserveGitDiffPathspecCovers(
	pathspecs []codexObserveGitDiffPathspec,
	relative string,
) bool {
	relative = filepath.Clean(relative)
	for _, pathspec := range pathspecs {
		root := filepath.Clean(pathspec.relative)
		if runtime.GOOS == "windows" {
			if strings.EqualFold(root, relative) {
				return true
			}
		} else if root == relative {
			return true
		}
		if !pathspec.directory {
			continue
		}
		descendant, err := filepath.Rel(root, relative)
		if err == nil && descendant != "." && descendant != ".." &&
			!strings.HasPrefix(descendant, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// codexToolResultContentScope derives result provenance only from the
// typed Codex hook envelope. Results remain untrusted unless the adapter can
// physically prove a read of explicit test fixtures or bundled guardrail rule
// sources. That narrow source scope keeps trust, secret, and PII matches as
// LOW detection-only telemetry while removing action-category literals and
// canonical public examples; ordinary source, process, mixed, and external
// output remains untrusted and fully alertable.
func codexToolResultContentScope(req codexHookRequest) ruleContentScope {
	toolName := strings.TrimSpace(codexToolName(req))
	if strings.TrimSpace(req.MCPServerName) != "" ||
		strings.TrimSpace(payloadString(req.Payload, "mcp_server_name")) != "" ||
		serverFromMCPToolName(toolName) != "" {
		return ruleContentScopeUntrusted
	}
	if codexExternalContentTool(toolName) {
		return ruleContentScopeUntrusted
	}

	facts := actionfacts.Analyze(actionfacts.Input{
		Tool:       toolName,
		Args:       codexToolArgs(req),
		CWD:        req.CWD,
		ActiveHome: trustedSameHostHome(),
	})
	if len(facts.Network) != 0 {
		return ruleContentScopeUntrusted
	}

	if codexLocalReadTool(toolName) {
		path := codexExactMapString(req.ToolInput,
			"file_path", "filePath", "path", "filename", "file")
		if trustedFixtureOrGuardrailSourcePath(path, req.CWD) {
			return ruleContentScopeSource
		}
		return ruleContentScopeUntrusted
	}
	// Every shell-capable envelope must pass a complete command-chain proof.
	// Falling through to the generic PathFacts branch would let a trusted read
	// launder synthetic sibling output (for example Get-Content fixture; then
	// Write-Output secret) because only the read contributes a path fact.
	if codexShellExecutionTool(toolName) {
		command := codexExactMapString(req.ToolInput, "command", "cmd", "script")
		if codexStaticSafeReaderSourceScope(command, facts, req.CWD, toolName) {
			return ruleContentScopeSource
		}
		return ruleContentScopeUntrusted
	}
	// Unknown/custom tools remain untrusted even when ActionFacts happens to
	// expose one trusted read path. Path facts do not prove that the tool emitted
	// only that file; it may append arbitrary synthetic or process output. The
	// only source-scope entrances are therefore typed local reads and complete,
	// allowlisted shell-reader proofs above.
	return ruleContentScopeUntrusted
}

func codexObserveWorkspaceSourceProofForRequest(req codexHookRequest) codexObserveSourceProof {
	toolName := strings.TrimSpace(codexToolName(req))
	if strings.TrimSpace(req.MCPServerName) != "" ||
		strings.TrimSpace(payloadString(req.Payload, "mcp_server_name")) != "" ||
		serverFromMCPToolName(toolName) != "" || codexExternalContentTool(toolName) {
		return codexObserveSourceUntrusted
	}
	facts := actionfacts.Analyze(actionfacts.Input{
		Tool:       toolName,
		Args:       codexToolArgs(req),
		CWD:        req.CWD,
		ActiveHome: trustedSameHostHome(),
	})
	if len(facts.Network) != 0 {
		return codexObserveSourceUntrusted
	}
	if codexLocalReadTool(toolName) {
		path := codexExactMapString(req.ToolInput,
			"file_path", "filePath", "path", "filename", "file")
		if trustedCodexObserveSourcePath(path, req.CWD) {
			return codexObserveSourceComplete
		}
		return codexObserveSourceUntrusted
	}
	if !codexShellExecutionTool(toolName) {
		return codexObserveSourceUntrusted
	}
	commandText := codexExactMapString(req.ToolInput, "command", "cmd", "script")
	if powerShellFacts, candidate := codexStaticPowerShellReaderFacts(
		commandText, facts, req.CWD, toolName,
	); candidate {
		if codexStaticPowerShellReaderSourceScopeWithTarget(
			powerShellFacts, req.CWD, trustedCodexObserveSourceTarget,
		) {
			return codexObserveSourceComplete
		}
		return codexObserveSourceUntrusted
	}
	if facts.Parse.Dialect != actionfacts.DialectPOSIX || len(facts.Commands) == 0 ||
		!codexStaticReaderParseStatus(facts.Parse) ||
		!codexStaticReaderShellStructureSafe(commandText) {
		return codexObserveSourceUntrusted
	}

	pipelineHasSource := make(map[int64]bool)
	sawSource := false
	sawStatus := false
	sawDiff := false
	sawReader := false
	for _, command := range facts.Commands {
		if command.Kind != actionfacts.CommandKindProcess ||
			command.Effect != actionfacts.EffectExecute ||
			!command.ArgvComplete || len(command.Argv) == 0 ||
			len(command.Redirects) != 0 || len(command.Wrappers) != 0 {
			return codexObserveSourceUntrusted
		}
		for _, argument := range command.Arguments {
			if argument.Expands || codexArgumentHasBraceExpansion(argument) {
				return codexObserveSourceUntrusted
			}
		}
		if codexReaderArgumentsContainAlertableContent(command.Argv) {
			return codexObserveSourceUntrusted
		}
		if command.Program == "git" {
			if targets, ok := codexObserveGitStatusTargets(command.Argv); ok {
				if command.PipelineID != 0 || sawStatus || sawDiff || sawReader {
					return codexObserveSourceUntrusted
				}
				for _, target := range targets {
					if !trustedCodexObserveSourceTarget(target, req.CWD, true) {
						return codexObserveSourceUntrusted
					}
				}
				sawStatus = true
				continue
			}
			if _, ok := codexObserveGitDiffPathspecs(command.Argv, req.CWD); ok {
				if command.PipelineID != 0 || sawDiff || sawReader {
					return codexObserveSourceUntrusted
				}
				sawDiff = true
				sawSource = true
				continue
			}
			return codexObserveSourceUntrusted
		}
		if sawDiff {
			return codexObserveSourceUntrusted
		}

		inputs, ok := codexStaticReaderCommandInputs(command.Program, command.Argv)
		if !ok {
			return codexObserveSourceUntrusted
		}
		for _, target := range inputs.targets {
			if !trustedCodexObserveSourceTarget(
				target.value, req.CWD, target.allowDirectory,
			) {
				return codexObserveSourceUntrusted
			}
		}
		if inputs.readsStdin && inputs.hasDataTarget {
			return codexObserveSourceUntrusted
		}
		if inputs.hasDataTarget {
			sawReader = true
			sawSource = true
			if command.PipelineID != 0 {
				pipelineHasSource[command.PipelineID] = true
			}
			continue
		}
		if !inputs.readsStdin || command.PipelineID == 0 ||
			!pipelineHasSource[command.PipelineID] {
			return codexObserveSourceUntrusted
		}
	}
	if !sawSource {
		return codexObserveSourceUntrusted
	}
	if sawDiff {
		return codexObserveSourceVerifiedDiff
	}
	if sawStatus {
		return codexObserveSourceMixedStatus
	}
	return codexObserveSourceComplete
}

// codexObserveGitStatusTargets accepts only the stable line-oriented status
// formats that the mixed-result splitter can keep untrusted. It rejects NUL
// output, configuration/pager overrides, arbitrary git subcommands, and
// dynamic pathspec features.
func codexObserveGitStatusTargets(argv []string) ([]string, bool) {
	if len(argv) < 3 || argv[0] != "git" {
		return nil, false
	}
	i := 1
	for i < len(argv) && argv[i] != "status" {
		switch argv[i] {
		case "--no-pager", "--literal-pathspecs":
			i++
		default:
			return nil, false
		}
	}
	if i >= len(argv) || argv[i] != "status" {
		return nil, false
	}
	i++
	shortFormat := false
	options := true
	var targets []string
	for ; i < len(argv); i++ {
		argument := argv[i]
		if options && argument == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(argument, "-") {
			switch {
			case argument == "--short" || argument == "-s" ||
				argument == "--porcelain" || argument == "--porcelain=v1":
				shortFormat = true
			case argument == "--branch" || argument == "-b" ||
				argument == "--show-stash" || argument == "--ahead-behind" ||
				argument == "--no-ahead-behind" || argument == "--renames" ||
				argument == "--no-renames" ||
				strings.HasPrefix(argument, "--find-renames=") ||
				strings.HasPrefix(argument, "--untracked-files=") ||
				strings.HasPrefix(argument, "--ignored=") ||
				argument == "-uno" || argument == "-unormal" || argument == "-uall":
			default:
				return nil, false
			}
			continue
		}
		if options || strings.HasPrefix(argument, ":(") {
			return nil, false
		}
		targets = append(targets, argument)
	}
	return targets, shortFormat
}

// codexObserveGitDiffPathspecs accepts only a working-tree unified diff with
// an explicit `--` path boundary and one or more static, physically validated
// workspace-source pathspecs. The output parser supplies the actual provenance
// boundary, so the common `git diff -- path` form is eligible; explicit pager,
// config, external-helper, textconv, output-rewriting, revision, and alternate
// repository controls remain rejected.
func codexObserveGitDiffPathspecs(
	argv []string,
	cwd string,
) ([]codexObserveGitDiffPathspec, bool) {
	if len(argv) < 4 || argv[0] != "git" {
		return nil, false
	}
	i := 1
	if argv[i] == "--no-pager" || argv[i] == "-P" {
		i++
	}
	if i >= len(argv) || argv[i] != "diff" {
		return nil, false
	}
	i++
	for i < len(argv) && argv[i] != "--" {
		argument := argv[i]
		switch argument {
		case "-p", "-u", "--patch", "--no-ext-diff", "--no-textconv",
			"--no-color", "--no-renames", "--minimal", "--patience",
			"--histogram", "-w", "-b", "--ignore-space-at-eol",
			"--ignore-cr-at-eol", "--ignore-blank-lines":
			i++
			continue
		case "-U", "--unified", "--inter-hunk-context":
			if !codexConsumeOptionValue(argv, &i) || !codexUnsignedDecimal(argv[i]) {
				return nil, false
			}
			i++
			continue
		}
		switch {
		case strings.HasPrefix(argument, "-U") && len(argument) > 2:
			if !codexUnsignedDecimal(argument[2:]) {
				return nil, false
			}
		case strings.HasPrefix(argument, "--unified="):
			if !codexUnsignedDecimal(strings.TrimPrefix(argument, "--unified=")) {
				return nil, false
			}
		case strings.HasPrefix(argument, "--inter-hunk-context="):
			if !codexUnsignedDecimal(strings.TrimPrefix(argument, "--inter-hunk-context=")) {
				return nil, false
			}
		default:
			// This includes revisions, --cached/--staged, --no-index,
			// pager/config/repository selectors, output format/rewriting
			// controls, external helpers, textconv, and unknown options.
			return nil, false
		}
		i++
	}
	if i >= len(argv) || argv[i] != "--" || i+1 >= len(argv) {
		return nil, false
	}

	pathspecs := make([]codexObserveGitDiffPathspec, 0, len(argv)-i-1)
	seen := make(map[string]struct{})
	for i++; i < len(argv); i++ {
		pathspec := argv[i]
		if pathspec == "" || strings.HasPrefix(pathspec, ":") ||
			strings.ContainsAny(pathspec, "*?[") ||
			!trustedCodexObserveSourceTarget(pathspec, cwd, true) {
			return nil, false
		}
		relative, ok := trustedPhysicalWorkspaceRelativePath(pathspec, cwd)
		if !ok || !codexObserveSourceRelativePath(relative) {
			return nil, false
		}
		realCWD, err := filepath.EvalSymlinks(filepath.Clean(cwd))
		if err != nil || !filepath.IsAbs(realCWD) {
			return nil, false
		}
		info, err := os.Lstat(filepath.Join(realCWD, relative))
		if err != nil || !info.Mode().IsRegular() && !info.IsDir() {
			return nil, false
		}
		key := filepath.Clean(relative)
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		pathspecs = append(pathspecs, codexObserveGitDiffPathspec{
			relative: relative, directory: info.IsDir(),
		})
	}
	return pathspecs, len(pathspecs) != 0
}

func codexObserveGitDiffPathspecsForRequest(
	req codexHookRequest,
) ([]codexObserveGitDiffPathspec, bool) {
	toolName := strings.TrimSpace(codexToolName(req))
	if !codexShellExecutionTool(toolName) ||
		strings.TrimSpace(req.MCPServerName) != "" ||
		strings.TrimSpace(payloadString(req.Payload, "mcp_server_name")) != "" ||
		serverFromMCPToolName(toolName) != "" || codexExternalContentTool(toolName) {
		return nil, false
	}
	facts := actionfacts.Analyze(actionfacts.Input{
		Tool:       toolName,
		Args:       codexToolArgs(req),
		CWD:        req.CWD,
		ActiveHome: trustedSameHostHome(),
	})
	commandText := codexExactMapString(req.ToolInput, "command", "cmd", "script")
	if len(facts.Network) != 0 || facts.Parse.Dialect != actionfacts.DialectPOSIX ||
		len(facts.Commands) == 0 || !codexStaticReaderParseStatus(facts.Parse) ||
		!codexStaticReaderShellStructureSafe(commandText) {
		return nil, false
	}

	var pathspecs []codexObserveGitDiffPathspec
	sawStatus := false
	sawDiff := false
	for _, command := range facts.Commands {
		if command.Kind != actionfacts.CommandKindProcess ||
			command.Effect != actionfacts.EffectExecute || !command.ArgvComplete ||
			len(command.Argv) == 0 || command.PipelineID != 0 ||
			len(command.Redirects) != 0 || len(command.Wrappers) != 0 {
			return nil, false
		}
		for _, argument := range command.Arguments {
			if argument.Expands || codexArgumentHasBraceExpansion(argument) {
				return nil, false
			}
		}
		if codexReaderArgumentsContainAlertableContent(command.Argv) ||
			command.Program != "git" {
			return nil, false
		}
		if targets, ok := codexObserveGitStatusTargets(command.Argv); ok {
			if sawStatus || sawDiff {
				return nil, false
			}
			for _, target := range targets {
				if !trustedCodexObserveSourceTarget(target, req.CWD, true) {
					return nil, false
				}
			}
			sawStatus = true
			continue
		}
		var ok bool
		pathspecs, ok = codexObserveGitDiffPathspecs(command.Argv, req.CWD)
		if !ok || sawDiff {
			return nil, false
		}
		sawDiff = true
	}
	return pathspecs, sawDiff && len(pathspecs) != 0
}

// codexExactMapString returns the first non-empty string value without
// normalizing any bytes. Typed file-reader paths are already decoded by the
// hook's JSON boundary; trimming them would prove a different filename than
// the reader actually opened.
func codexExactMapString(values map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		value, ok := values[key].(string)
		if ok && value != "" {
			return value
		}
	}
	return ""
}

func codexShellExecutionTool(tool string) bool {
	name := strings.ToLower(strings.TrimSpace(tool))
	name = strings.ReplaceAll(name, `\`, "/")
	if slash := strings.LastIndexByte(name, '/'); slash >= 0 {
		name = name[slash+1:]
	}
	if trustedBashExecutionTool(name) {
		return true
	}
	switch name {
	case "sh", "dash", "mksh", "fish", "powershell", "powershell.exe",
		"pwsh", "pwsh.exe", "cmd", "cmd.exe":
		return true
	default:
		return false
	}
}

type codexStaticReaderInputs struct {
	targets       []codexStaticReaderTarget
	hasDataTarget bool
	readsStdin    bool
}

type codexStaticReaderTarget struct {
	value          string
	allowDirectory bool
}

// codexStaticSafeReaderSourceScope is a fail-closed provenance proof for
// shell-backed PostToolUse results. ActionFacts deliberately leaves the
// operand grammars of tools such as sed and awk partial. For this narrow
// source classification we therefore inspect its already parsed, static argv
// projection, but only accept an entire command chain made up of known
// read/search programs. Every file or directory operand must physically
// resolve to a fixture or shipped detector source; redirects, expansion,
// wrappers, embedded execution, mutation, and unknown options reject the
// whole result.
func codexStaticSafeReaderSourceScope(
	command string,
	facts actionfacts.Facts,
	cwd string,
	toolName string,
) bool {
	if powerShellFacts, candidate := codexStaticPowerShellReaderFacts(
		command, facts, cwd, toolName,
	); candidate {
		return codexStaticPowerShellReaderSourceScope(powerShellFacts, cwd)
	}
	if facts.Parse.Dialect != actionfacts.DialectPOSIX {
		return false
	}
	if len(facts.Commands) == 0 || !codexStaticReaderParseStatus(facts.Parse) ||
		!codexStaticReaderShellStructureSafe(command) {
		return false
	}
	pipelineHasSource := make(map[int64]bool)
	sawDataTarget := false
	for _, command := range facts.Commands {
		if command.Kind != actionfacts.CommandKindProcess ||
			command.Effect != actionfacts.EffectExecute ||
			!command.ArgvComplete || len(command.Argv) == 0 ||
			len(command.Redirects) != 0 || len(command.Wrappers) != 0 {
			return false
		}
		for _, argument := range command.Arguments {
			if argument.Expands || codexArgumentHasBraceExpansion(argument) {
				return false
			}
		}
		if codexReaderArgumentsContainAlertableContent(command.Argv) {
			return false
		}
		inputs, ok := codexStaticReaderCommandInputs(command.Program, command.Argv)
		if !ok {
			return false
		}
		for _, target := range inputs.targets {
			if !trustedFixtureOrGuardrailSourceTarget(
				target.value, cwd, target.allowDirectory,
			) {
				return false
			}
		}
		if inputs.readsStdin && inputs.hasDataTarget {
			// A command that merges an explicit source with ambient stdin has
			// mixed provenance even when the explicit path is trusted.
			return false
		}
		if inputs.hasDataTarget {
			sawDataTarget = true
			if command.PipelineID != 0 {
				pipelineHasSource[command.PipelineID] = true
			}
			continue
		}
		if !inputs.readsStdin || command.PipelineID == 0 ||
			!pipelineHasSource[command.PipelineID] {
			return false
		}
	}
	return sawDataTarget
}

// codexStaticPowerShellReaderFacts selects the PowerShell grammar only for an
// explicit PowerShell/CMD tool or for a generic execution envelope running on
// Windows. This preserves Unix `type`/`gc` semantics while covering the same
// generic exec_command envelope Codex uses on Windows.
func codexStaticPowerShellReaderFacts(
	command string,
	facts actionfacts.Facts,
	cwd string,
	toolName string,
) (actionfacts.Facts, bool) {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return actionfacts.Facts{}, false
	}
	program := strings.ToLower(fields[0])
	switch program {
	case "get-content", "gc", "type", "select-string":
	default:
		return actionfacts.Facts{}, false
	}

	tool := strings.ToLower(strings.TrimSpace(toolName))
	tool = strings.ReplaceAll(tool, `\`, "/")
	if slash := strings.LastIndexByte(tool, '/'); slash >= 0 {
		tool = tool[slash+1:]
	}
	explicitWindowsShell := tool == "powershell" || tool == "powershell.exe" ||
		tool == "pwsh" || tool == "pwsh.exe" || tool == "cmd" || tool == "cmd.exe"
	windowsGeneric := runtime.GOOS == "windows" && trustedBashExecutionTool(tool)
	if !explicitWindowsShell && !windowsGeneric {
		return actionfacts.Facts{}, false
	}

	if facts.Parse.Dialect == actionfacts.DialectPowerShell ||
		facts.Parse.Dialect == actionfacts.DialectCMD {
		return facts, true
	}
	// Short aliases with relative paths do not carry enough lexical signal for
	// generic dialect inference. On Windows, retry them under the explicit,
	// bounded PowerShell grammar; the complete proof below remains fail closed.
	return actionfacts.Analyze(actionfacts.Input{
		Tool:        "powershell",
		Command:     command,
		CWD:         cwd,
		ActiveHome:  trustedSameHostHome(),
		DialectHint: actionfacts.DialectPowerShell,
	}), true
}

func codexStaticPowerShellReaderSourceScope(facts actionfacts.Facts, cwd string) bool {
	return codexStaticPowerShellReaderSourceScopeWithTarget(
		facts, cwd, trustedFixtureOrGuardrailSourceTarget,
	)
}

func codexStaticPowerShellReaderSourceScopeWithTarget(
	facts actionfacts.Facts,
	cwd string,
	trustedTarget func(string, string, bool) bool,
) bool {
	if !codexStaticPowerShellReaderParseStatus(facts.Parse) ||
		len(facts.Commands) != 1 || len(facts.Network) != 0 ||
		len(facts.DataFlows) != 0 {
		return false
	}
	command := facts.Commands[0]
	if command.Kind != actionfacts.CommandKindProcess ||
		(command.Dialect != actionfacts.DialectPowerShell &&
			command.Dialect != actionfacts.DialectCMD) ||
		command.Effect != actionfacts.EffectExecute || !command.ArgvComplete ||
		len(command.Argv) == 0 || command.PipelineID != 0 ||
		len(command.Redirects) != 0 || len(command.Wrappers) != 0 ||
		len(command.Arguments) != len(command.Argv) {
		return false
	}
	for _, argument := range command.Arguments {
		if argument.Expands || argument.Quote == actionfacts.QuoteMixed {
			return false
		}
	}
	if codexReaderArgumentsContainAlertableContent(command.Argv) {
		return false
	}

	var inputs codexStaticReaderInputs
	var ok bool
	switch strings.ToLower(command.Program) {
	case "get-content", "gc", "type":
		inputs, ok = codexPowerShellGetContentInputs(command)
	case "select-string":
		inputs, ok = codexPowerShellSelectStringInputs(command)
	default:
		return false
	}
	if !ok || !inputs.hasDataTarget || inputs.readsStdin {
		return false
	}
	for _, target := range inputs.targets {
		path, ok := codexPowerShellHostPath(target.value)
		if !ok || !trustedTarget(path, cwd, false) {
			return false
		}
	}
	return true
}

// Reader tools can reflect non-path argv into stderr even when the command
// fails (for example an invalid rg pattern). Codex PostToolUse does not carry
// an authoritative exit status, so a credential or strong trust directive in
// argv cannot be proven to have originated in the physically checked source
// file. Keep those results untrusted instead of laundering the reflected bytes
// through source scope.
func codexReaderArgumentsContainAlertableContent(argv []string) bool {
	if len(argv) == 0 {
		return true
	}
	for _, finding := range scanContentRulesForConnector(
		"", strings.Join(argv, "\n"), "", ruleContentScopeUntrusted,
	) {
		if severityRank[finding.Severity] >= severityRank["HIGH"] {
			return true
		}
	}
	return false
}

func codexStaticPowerShellReaderParseStatus(parse actionfacts.ParseResult) bool {
	switch parse.Status {
	case actionfacts.StatusComplete:
		return true
	case actionfacts.StatusPartial:
		if len(parse.Issues) == 0 {
			return false
		}
		for _, issue := range parse.Issues {
			if issue != actionfacts.IssueUnknownOperandGrammar {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func codexPowerShellGetContentInputs(
	command actionfacts.CommandFact,
) (codexStaticReaderInputs, bool) {
	var inputs codexStaticReaderInputs
	for i := 1; i < len(command.Argv); i++ {
		argument := command.Argv[i]
		lower := strings.ToLower(argument)
		parameter := command.Arguments[i].Quote == actionfacts.QuoteNone &&
			strings.HasPrefix(argument, "-")
		if parameter {
			switch lower {
			case "-path", "-literalpath":
				if !codexPowerShellConsumeValue(command, &i) ||
					!codexReaderTarget(&inputs, command.Argv[i], true) {
					return codexStaticReaderInputs{}, false
				}
			case "-encoding", "-delimiter":
				if !codexPowerShellConsumeValue(command, &i) {
					return codexStaticReaderInputs{}, false
				}
			case "-totalcount", "-tail", "-readcount":
				if !codexPowerShellConsumeValue(command, &i) ||
					!codexUnsignedDecimal(command.Argv[i]) {
					return codexStaticReaderInputs{}, false
				}
			case "-raw", "-force", "-asbytestream":
			default:
				// -Wait/-Stream, recursive/filtering parameters, common
				// wrappers, and unknown abbreviations are intentionally out.
				return codexStaticReaderInputs{}, false
			}
			continue
		}
		if !codexReaderTarget(&inputs, argument, true) {
			return codexStaticReaderInputs{}, false
		}
	}
	return inputs, inputs.hasDataTarget
}

func codexPowerShellSelectStringInputs(
	command actionfacts.CommandFact,
) (codexStaticReaderInputs, bool) {
	var inputs codexStaticReaderInputs
	patternProvided := false
	var positionals []string
	for i := 1; i < len(command.Argv); i++ {
		argument := command.Argv[i]
		lower := strings.ToLower(argument)
		parameter := command.Arguments[i].Quote == actionfacts.QuoteNone &&
			strings.HasPrefix(argument, "-")
		if parameter {
			switch lower {
			case "-path", "-literalpath":
				if !codexPowerShellConsumeValue(command, &i) ||
					!codexReaderTarget(&inputs, command.Argv[i], true) {
					return codexStaticReaderInputs{}, false
				}
			case "-pattern":
				if patternProvided || !codexPowerShellConsumeValue(command, &i) {
					return codexStaticReaderInputs{}, false
				}
				patternProvided = true
			case "-encoding", "-culture":
				if !codexPowerShellConsumeValue(command, &i) {
					return codexStaticReaderInputs{}, false
				}
			case "-simplematch", "-casesensitive", "-quiet", "-list",
				"-notmatch", "-allmatches", "-noemphasis":
			default:
				// InputObject, recurse/filter expansions, Context arrays, and
				// unknown/abbreviated parameters are not source-proven.
				return codexStaticReaderInputs{}, false
			}
			continue
		}
		positionals = append(positionals, argument)
	}
	if !patternProvided {
		if len(positionals) == 0 {
			return codexStaticReaderInputs{}, false
		}
		patternProvided = true
		positionals = positionals[1:]
	}
	for _, target := range positionals {
		if !codexReaderTarget(&inputs, target, true) {
			return codexStaticReaderInputs{}, false
		}
	}
	return inputs, patternProvided && inputs.hasDataTarget
}

func codexPowerShellConsumeValue(command actionfacts.CommandFact, index *int) bool {
	if *index+1 >= len(command.Argv) {
		return false
	}
	*index++
	return command.Argv[*index] != "" &&
		(command.Arguments[*index].Quote != actionfacts.QuoteNone ||
			!strings.HasPrefix(command.Argv[*index], "-"))
}

func codexPowerShellHostPath(value string) (string, bool) {
	if value == "" || strings.IndexByte(value, 0) >= 0 ||
		strings.Contains(value, "::") || strings.HasPrefix(value, `\\?\`) ||
		strings.HasPrefix(value, `\\.\`) {
		return "", false
	}
	if colon := strings.IndexByte(value, ':'); colon >= 0 {
		if colon != 1 || len(value) < 3 ||
			(value[2] != '\\' && value[2] != '/') ||
			strings.IndexByte(value[colon+1:], ':') >= 0 {
			return "", false
		}
		if runtime.GOOS != "windows" {
			return "", false
		}
	}
	if runtime.GOOS != "windows" {
		if strings.HasPrefix(value, `\\`) {
			return "", false
		}
		value = strings.ReplaceAll(value, `\`, "/")
	}
	return value, true
}

// codexStaticReaderShellStructureSafe independently rejects executable shell
// constructs that the POSIX fact projection may intentionally skip. In
// particular, a function declaration can redefine an allowlisted reader while
// ActionFacts retains only the later invocation. Ordinary static pipelines and
// &&/|| chains remain eligible and are still checked command-by-command above.
func codexStaticReaderShellStructureSafe(command string) bool {
	if command == "" {
		return false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(
		strings.NewReader(command), "",
	)
	if err != nil {
		return false
	}
	safe := true
	syntax.Walk(file, func(node syntax.Node) bool {
		if !safe || node == nil {
			return safe
		}
		switch typed := node.(type) {
		case *syntax.FuncDecl, *syntax.CmdSubst, *syntax.ProcSubst,
			*syntax.Subshell, *syntax.Block, *syntax.IfClause,
			*syntax.WhileClause, *syntax.ForClause, *syntax.CaseClause,
			*syntax.ArithmCmd, *syntax.TestClause, *syntax.DeclClause,
			*syntax.LetClause, *syntax.TimeClause, *syntax.CoprocClause:
			safe = false
			return false
		case *syntax.Stmt:
			if typed.Negated || typed.Background || typed.Coprocess || typed.Disown ||
				len(typed.Redirs) != 0 {
				safe = false
				return false
			}
		case *syntax.CallExpr:
			if len(typed.Assigns) != 0 {
				safe = false
				return false
			}
		}
		return true
	})
	return safe
}

// ActionFacts marks ordinary glob and tilde expansion, but its POSIX
// projection intentionally leaves Bash/Zsh brace expansion as a literal.
// Re-run mvdan's brace splitter for unquoted/mixed argv values before trusting
// any reader command, otherwise a physically verified literal `{a,b}` file can
// mask the two different files the shell actually read.
func codexArgumentHasBraceExpansion(argument actionfacts.ArgumentFact) bool {
	if argument.Value == "" || argument.Quote == actionfacts.QuoteSingle ||
		argument.Quote == actionfacts.QuoteDouble {
		return false
	}
	word := &syntax.Word{Parts: []syntax.WordPart{
		&syntax.Lit{Value: argument.Value},
	}}
	return syntax.SplitBraces(word)
}

func codexStaticReaderParseStatus(parse actionfacts.ParseResult) bool {
	switch parse.Status {
	case actionfacts.StatusComplete:
		return true
	case actionfacts.StatusPartial:
		if len(parse.Issues) == 0 {
			return false
		}
		for _, issue := range parse.Issues {
			if issue != actionfacts.IssueUnknownOperandGrammar &&
				issue != actionfacts.IssueUnsupportedConstruct {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func codexStaticReaderCommandInputs(program string, argv []string) (codexStaticReaderInputs, bool) {
	switch program {
	case "cat":
		return codexCatInputs(argv)
	case "head", "tail":
		return codexHeadTailInputs(program, argv)
	case "sed":
		return codexSedInputs(argv)
	case "awk":
		return codexAwkInputs(argv)
	case "grep", "rg", "ripgrep":
		return codexPatternSearchInputs(program, argv)
	case "find":
		return codexFindInputs(argv)
	case "fd":
		return codexFDInputs(argv)
	case "git":
		return codexGitDiffInputs(argv)
	default:
		return codexStaticReaderInputs{}, false
	}
}

func codexReaderTarget(inputs *codexStaticReaderInputs, value string, data bool) bool {
	return codexReaderTargetWithType(inputs, value, data, false)
}

func codexReaderSearchTarget(inputs *codexStaticReaderInputs, value string, data bool) bool {
	return codexReaderTargetWithType(inputs, value, data, true)
}

func codexReaderTargetWithType(
	inputs *codexStaticReaderInputs,
	value string,
	data bool,
	allowDirectory bool,
) bool {
	if value == "" {
		return false
	}
	if value == "-" {
		if !data {
			return false
		}
		inputs.readsStdin = true
		return true
	}
	inputs.targets = append(inputs.targets, codexStaticReaderTarget{
		value: value, allowDirectory: allowDirectory,
	})
	inputs.hasDataTarget = inputs.hasDataTarget || data
	return true
}

func codexCatInputs(argv []string) (codexStaticReaderInputs, bool) {
	var inputs codexStaticReaderInputs
	options := true
	for _, arg := range argv[1:] {
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "--") {
			switch arg {
			case "--show-all", "--number-nonblank", "--show-ends", "--number",
				"--squeeze-blank", "--show-tabs", "--show-nonprinting":
				continue
			default:
				return codexStaticReaderInputs{}, false
			}
		}
		if options && len(arg) > 1 && arg[0] == '-' {
			if !codexShortOptionBundle(arg[1:], "AbeEnstTuv") {
				return codexStaticReaderInputs{}, false
			}
			continue
		}
		if !codexReaderTarget(&inputs, arg, true) {
			return codexStaticReaderInputs{}, false
		}
	}
	if !inputs.hasDataTarget {
		inputs.readsStdin = true
	}
	return inputs, true
}

func codexHeadTailInputs(program string, argv []string) (codexStaticReaderInputs, bool) {
	var inputs codexStaticReaderInputs
	options := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "--") {
			key, _, joined := strings.Cut(arg, "=")
			switch key {
			case "--lines", "--bytes":
				if !joined && !codexConsumeOptionValue(argv, &i) {
					return codexStaticReaderInputs{}, false
				}
				continue
			case "--pid", "--sleep-interval", "--max-unchanged-stats":
				if program != "tail" || !joined && !codexConsumeOptionValue(argv, &i) {
					return codexStaticReaderInputs{}, false
				}
				continue
			case "--quiet", "--silent", "--verbose", "--zero-terminated":
				if joined {
					return codexStaticReaderInputs{}, false
				}
				continue
			case "--follow":
				if program != "tail" {
					return codexStaticReaderInputs{}, false
				}
				continue
			case "--retry":
				if program != "tail" || joined {
					return codexStaticReaderInputs{}, false
				}
				continue
			default:
				return codexStaticReaderInputs{}, false
			}
		}
		if options && len(arg) > 1 && arg[0] == '-' {
			switch {
			case arg == "-n" || arg == "-c" || program == "tail" && arg == "-s":
				if !codexConsumeOptionValue(argv, &i) {
					return codexStaticReaderInputs{}, false
				}
				continue
			case strings.HasPrefix(arg, "-n") && len(arg) > 2,
				strings.HasPrefix(arg, "-c") && len(arg) > 2,
				codexSignedDecimal(arg):
				continue
			}
			allowed := "qvz"
			if program == "tail" {
				allowed += "fFr"
			}
			if !codexShortOptionBundle(arg[1:], allowed) {
				return codexStaticReaderInputs{}, false
			}
			continue
		}
		if options && strings.HasPrefix(arg, "+") && codexSignedDecimal(arg) {
			continue
		}
		if !codexReaderTarget(&inputs, arg, true) {
			return codexStaticReaderInputs{}, false
		}
	}
	if !inputs.hasDataTarget {
		inputs.readsStdin = true
	}
	return inputs, true
}

func codexSedInputs(argv []string) (codexStaticReaderInputs, bool) {
	var inputs codexStaticReaderInputs
	var scripts []string
	var positionals []string
	options := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "--") {
			key, value, joined := strings.Cut(arg, "=")
			switch key {
			case "--expression":
				if !joined {
					if !codexConsumeOptionValue(argv, &i) {
						return codexStaticReaderInputs{}, false
					}
					value = argv[i]
				}
				scripts = append(scripts, value)
			case "--quiet", "--silent", "--regexp-extended", "--separate",
				"--unbuffered", "--null-data", "--sandbox":
				if joined {
					return codexStaticReaderInputs{}, false
				}
			default:
				// --file and --in-place make provenance depend on another
				// program or mutate the input; unknown options fail closed.
				return codexStaticReaderInputs{}, false
			}
			continue
		}
		if options && len(arg) > 1 && arg[0] == '-' {
			switch {
			case arg == "-e":
				if !codexConsumeOptionValue(argv, &i) {
					return codexStaticReaderInputs{}, false
				}
				scripts = append(scripts, argv[i])
				continue
			case strings.HasPrefix(arg, "-e") && len(arg) > 2:
				scripts = append(scripts, arg[2:])
				continue
			case strings.HasPrefix(arg, "-i") || strings.HasPrefix(arg, "-f"):
				return codexStaticReaderInputs{}, false
			case codexShortOptionBundle(arg[1:], "nErsuz"):
				continue
			default:
				return codexStaticReaderInputs{}, false
			}
		}
		positionals = append(positionals, arg)
	}
	if len(scripts) == 0 {
		if len(positionals) == 0 {
			return codexStaticReaderInputs{}, false
		}
		scripts = append(scripts, positionals[0])
		positionals = positionals[1:]
	}
	for _, script := range scripts {
		if !codexSafeSedProgram(script) {
			return codexStaticReaderInputs{}, false
		}
	}
	for _, target := range positionals {
		if !codexReaderTarget(&inputs, target, true) {
			return codexStaticReaderInputs{}, false
		}
	}
	if !inputs.hasDataTarget {
		inputs.readsStdin = true
	}
	return inputs, true
}

func codexSafeSedProgram(program string) bool {
	sawCommand := false
	for _, char := range strings.TrimSpace(program) {
		switch {
		case char >= '0' && char <= '9', strings.ContainsRune(" \t\r\n$,;{}!+-~", char):
		case strings.ContainsRune("pPdDqQnNl", char), char == '=':
			sawCommand = true
		default:
			return false
		}
	}
	return sawCommand
}

func codexAwkInputs(argv []string) (codexStaticReaderInputs, bool) {
	var inputs codexStaticReaderInputs
	var program string
	options := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if program == "" && options && strings.HasPrefix(arg, "-F") {
			if arg == "-F" && !codexConsumeOptionValue(argv, &i) {
				return codexStaticReaderInputs{}, false
			}
			continue
		}
		if program == "" && options && strings.HasPrefix(arg, "-") {
			// Program files and variable assignments can introduce hidden
			// reads, writes, or execution and are intentionally unsupported.
			return codexStaticReaderInputs{}, false
		}
		if program == "" {
			program = arg
			continue
		}
		if !codexReaderTarget(&inputs, arg, true) {
			return codexStaticReaderInputs{}, false
		}
	}
	if !codexSafeAwkProgram(program) {
		return codexStaticReaderInputs{}, false
	}
	if !inputs.hasDataTarget {
		inputs.readsStdin = true
	}
	return inputs, true
}

func codexSafeAwkProgram(program string) bool {
	allowedIdentifiers := map[string]bool{
		"NR": true, "FNR": true, "NF": true, "print": true, "next": true,
		"length": true, "substr": true, "index": true, "tolower": true, "toupper": true,
	}
	for i := 0; i < len(program); {
		char := program[i]
		if char == '_' || char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' {
			start := i
			for i < len(program) {
				char = program[i]
				if char != '_' && !(char >= 'A' && char <= 'Z') &&
					!(char >= 'a' && char <= 'z') && !(char >= '0' && char <= '9') {
					break
				}
				i++
			}
			if !allowedIdentifiers[program[start:i]] {
				return false
			}
			continue
		}
		if char == '>' && (i+1 >= len(program) || program[i+1] != '=') {
			return false
		}
		if !strings.ContainsRune(" \t\r\n0123456789{}()[];,.+-*/%<>=!&?:$", rune(char)) {
			return false
		}
		i++
	}
	return strings.TrimSpace(program) != ""
}

func codexPatternSearchInputs(program string, argv []string) (codexStaticReaderInputs, bool) {
	var inputs codexStaticReaderInputs
	patternProvided := false
	options := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "--") {
			key, value, joined := strings.Cut(arg, "=")
			switch key {
			case "--no-config":
				if program == "grep" || joined {
					return codexStaticReaderInputs{}, false
				}
				// An explicit opt-out is safe but not mandatory. The Codex hook
				// does not carry an authoritative process environment, so an
				// inherited same-user RIPGREP_CONFIG_PATH cannot be distinguished
				// from ripgrep's ordinary defaults. Explicit assignments/wrappers
				// are still rejected by the whole-command ActionFacts proof, as are
				// argv features that execute preprocessors or decompressors.
				continue
			case "--regexp":
				if !joined && !codexConsumeOptionValue(argv, &i) {
					return codexStaticReaderInputs{}, false
				}
				patternProvided = true
				continue
			case "--file":
				if !joined {
					if !codexConsumeOptionValue(argv, &i) {
						return codexStaticReaderInputs{}, false
					}
					value = argv[i]
				}
				if !codexReaderTarget(&inputs, value, false) {
					return codexStaticReaderInputs{}, false
				}
				patternProvided = true
				continue
			case "--after-context", "--before-context", "--context":
				if !joined {
					if !codexConsumeOptionValue(argv, &i) {
						return codexStaticReaderInputs{}, false
					}
					value = argv[i]
				}
				if !codexUnsignedDecimal(value) {
					return codexStaticReaderInputs{}, false
				}
				continue
			case "--pre", "--pre-glob", "--follow", "--dereference-recursive",
				"--replace", "--label", "--path-separator", "--search-zip":
				return codexStaticReaderInputs{}, false
			case "--devices":
				// GNU grep can be told to read FIFOs/devices even during a
				// recursive walk. Only its explicit safe action is eligible;
				// ripgrep does not expose this option.
				if program != "grep" {
					return codexStaticReaderInputs{}, false
				}
				if !joined {
					if !codexConsumeOptionValue(argv, &i) {
						return codexStaticReaderInputs{}, false
					}
					value = argv[i]
				}
				if value != "skip" {
					return codexStaticReaderInputs{}, false
				}
				continue
			case "--directories":
				if program != "grep" {
					return codexStaticReaderInputs{}, false
				}
				if !joined {
					if !codexConsumeOptionValue(argv, &i) {
						return codexStaticReaderInputs{}, false
					}
					value = argv[i]
				}
				if value != "recurse" && value != "skip" {
					return codexStaticReaderInputs{}, false
				}
				continue
			}
			if codexSearchLongValueOption(key) {
				if !joined && !codexConsumeOptionValue(argv, &i) {
					return codexStaticReaderInputs{}, false
				}
				continue
			}
			if joined || !codexSearchLongFlag(key, program) {
				return codexStaticReaderInputs{}, false
			}
			continue
		}
		if options && len(arg) > 1 && arg[0] == '-' {
			if arg == "-R" || program != "grep" && (arg == "-L" || arg == "-z") {
				return codexStaticReaderInputs{}, false
			}
			switch {
			case arg == "-D" || arg == "-d":
				if program != "grep" || !codexConsumeOptionValue(argv, &i) ||
					(arg == "-D" && argv[i] != "skip") ||
					(arg == "-d" && argv[i] != "recurse" && argv[i] != "skip") {
					return codexStaticReaderInputs{}, false
				}
				continue
			case program == "grep" && strings.HasPrefix(arg, "-D") && len(arg) > 2:
				if arg[2:] != "skip" {
					return codexStaticReaderInputs{}, false
				}
				continue
			case program == "grep" && strings.HasPrefix(arg, "-d") && len(arg) > 2:
				if arg[2:] != "recurse" && arg[2:] != "skip" {
					return codexStaticReaderInputs{}, false
				}
				continue
			case arg == "-A" || arg == "-B" || arg == "-C":
				if !codexConsumeOptionValue(argv, &i) || !codexUnsignedDecimal(argv[i]) {
					return codexStaticReaderInputs{}, false
				}
				continue
			case len(arg) > 2 && (strings.HasPrefix(arg, "-A") ||
				strings.HasPrefix(arg, "-B") || strings.HasPrefix(arg, "-C")):
				if !codexUnsignedDecimal(arg[2:]) {
					return codexStaticReaderInputs{}, false
				}
				continue
			case arg == "-e" || arg == "-f":
				if !codexConsumeOptionValue(argv, &i) {
					return codexStaticReaderInputs{}, false
				}
				if arg == "-f" && !codexReaderTarget(&inputs, argv[i], false) {
					return codexStaticReaderInputs{}, false
				}
				patternProvided = true
				continue
			case strings.HasPrefix(arg, "-e") && len(arg) > 2:
				patternProvided = true
				continue
			case strings.HasPrefix(arg, "-f") && len(arg) > 2:
				if !codexReaderTarget(&inputs, arg[2:], false) {
					return codexStaticReaderInputs{}, false
				}
				patternProvided = true
				continue
			case codexSearchShortFlags(arg[1:], program):
				continue
			default:
				return codexStaticReaderInputs{}, false
			}
		}
		if !patternProvided {
			patternProvided = true
			continue
		}
		if !codexReaderSearchTarget(&inputs, arg, true) {
			return codexStaticReaderInputs{}, false
		}
	}
	if !patternProvided {
		return codexStaticReaderInputs{}, false
	}
	if !inputs.hasDataTarget {
		inputs.readsStdin = true
	}
	return inputs, true
}

func codexSearchLongValueOption(option string) bool {
	switch option {
	case "--binary-files", "--color",
		"--dfa-size-limit",
		"--encoding", "--engine", "--exclude", "--exclude-dir", "--glob",
		"--iglob", "--include", "--max-columns", "--max-count",
		"--max-depth", "--max-filesize",
		"--sort", "--sortr", "--type", "--type-not":
		return true
	default:
		return false
	}
}

func codexSearchLongFlag(option, program string) bool {
	switch option {
	case "--line-number", "--no-heading", "--hidden", "--no-ignore",
		"--fixed-strings", "--ignore-case", "--word-regexp", "--invert-match",
		"--files-with-matches", "--files-without-match", "--count",
		"--only-matching", "--quiet", "--text", "--binary", "--json",
		"--multiline", "--pcre2", "--crlf", "--one-file-system",
		"--no-messages", "--with-filename", "--no-filename":
		return true
	case "--recursive":
		return program == "grep"
	default:
		return false
	}
}

func codexSearchShortFlags(flags, program string) bool {
	allowed := "EFGPivwxcloqsbHhnIaUu"
	if program == "grep" {
		allowed += "rLz"
	}
	return codexShortOptionBundle(flags, allowed)
}

func codexUnsignedDecimal(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func codexFindInputs(argv []string) (codexStaticReaderInputs, bool) {
	var inputs codexStaticReaderInputs
	i := 1
	for i < len(argv) && (argv[i] == "-H" || argv[i] == "-P") {
		i++
	}
	if i < len(argv) && argv[i] == "-L" {
		return codexStaticReaderInputs{}, false
	}
	for i < len(argv) && !codexFindExpressionStart(argv[i]) {
		if !codexReaderSearchTarget(&inputs, argv[i], true) {
			return codexStaticReaderInputs{}, false
		}
		i++
	}
	if !inputs.hasDataTarget {
		return codexStaticReaderInputs{}, false
	}
	for i < len(argv) {
		arg := argv[i]
		switch arg {
		case "-delete", "-exec", "-execdir", "-ok", "-okdir", "-follow",
			"-fls", "-fprint", "-fprint0", "-fprintf", "-printf", "-files0-from":
			return codexStaticReaderInputs{}, false
		case "-anewer", "-cnewer", "-newer":
			if !codexConsumeOptionValue(argv, &i) ||
				!codexReaderTarget(&inputs, argv[i], false) {
				return codexStaticReaderInputs{}, false
			}
		case "-amin", "-atime", "-cmin", "-ctime", "-gid", "-group", "-ilname",
			"-iname", "-inum", "-ipath", "-iregex", "-links", "-lname", "-maxdepth",
			"-mindepth", "-mmin", "-mtime", "-name", "-newermt", "-perm", "-regex",
			"-size", "-type", "-uid", "-used", "-user", "-wholename", "-fstype":
			if !codexConsumeOptionValue(argv, &i) {
				return codexStaticReaderInputs{}, false
			}
		case "!", "(", ")", ",", "-a", "-and", "-o", "-or", "-not",
			"-empty", "-false", "-true", "-mount", "-xdev", "-readable", "-writable",
			"-executable", "-print", "-print0", "-prune", "-quit", "-ls", "-depth":
		default:
			return codexStaticReaderInputs{}, false
		}
		i++
	}
	return inputs, true
}

func codexFindExpressionStart(value string) bool {
	return value == "!" || value == "(" || value == ")" || value == "," ||
		strings.HasPrefix(value, "-")
}

func codexFDInputs(argv []string) (codexStaticReaderInputs, bool) {
	var inputs codexStaticReaderInputs
	patternSeen := false
	options := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "--") {
			key, value, joined := strings.Cut(arg, "=")
			switch key {
			case "--exec", "--exec-batch", "--follow", "--format", "--base-directory":
				return codexStaticReaderInputs{}, false
			case "--search-path":
				if !joined {
					if !codexConsumeOptionValue(argv, &i) {
						return codexStaticReaderInputs{}, false
					}
					value = argv[i]
				}
				if !codexReaderSearchTarget(&inputs, value, true) {
					return codexStaticReaderInputs{}, false
				}
				continue
			}
			if codexFDLongValueOption(key) {
				if !joined && !codexConsumeOptionValue(argv, &i) {
					return codexStaticReaderInputs{}, false
				}
				continue
			}
			if joined || !codexFDLongFlag(key) {
				return codexStaticReaderInputs{}, false
			}
			continue
		}
		if options && len(arg) > 1 && arg[0] == '-' {
			if arg == "-x" || arg == "-X" || arg == "-L" {
				return codexStaticReaderInputs{}, false
			}
			if strings.Contains("-e-t-d-j-E-o-c", arg) && len(arg) == 2 {
				if !codexConsumeOptionValue(argv, &i) {
					return codexStaticReaderInputs{}, false
				}
				continue
			}
			if !codexShortOptionBundle(arg[1:], "HIisga0p1q") {
				return codexStaticReaderInputs{}, false
			}
			continue
		}
		if !patternSeen {
			patternSeen = true
			continue
		}
		if !codexReaderSearchTarget(&inputs, arg, true) {
			return codexStaticReaderInputs{}, false
		}
	}
	return inputs, patternSeen && inputs.hasDataTarget
}

func codexFDLongValueOption(option string) bool {
	switch option {
	case "--extension", "--type", "--max-depth", "--min-depth", "--threads",
		"--exclude", "--size", "--changed-within", "--changed-before", "--owner",
		"--color":
		return true
	default:
		return false
	}
}

func codexFDLongFlag(option string) bool {
	switch option {
	case "--hidden", "--no-ignore", "--ignore-case", "--case-sensitive", "--glob",
		"--regex", "--absolute-path", "--print0", "--full-path", "--quiet",
		"--one-file-system", "--strip-cwd-prefix", "--show-errors", "--no-require-git":
		return true
	default:
		return false
	}
}

// codexGitDiffInputs accepts only the common built-in working-tree diff form
// used to review detector/test changes. The explicit `--` boundary is
// mandatory, every pathspec must be a static trusted source target, and the
// option allowlist requires Git's pager, external diff, and textconv lanes to
// be disabled and excludes output rewriting, repository/config selection,
// revisions, and pathspec magic.
func codexGitDiffInputs(argv []string) (codexStaticReaderInputs, bool) {
	var inputs codexStaticReaderInputs
	if len(argv) < 4 || argv[0] != "git" {
		return inputs, false
	}

	i := 1
	if argv[i] != "--no-pager" && argv[i] != "-P" {
		return codexStaticReaderInputs{}, false
	}
	i++
	if i >= len(argv) || argv[i] != "diff" {
		return codexStaticReaderInputs{}, false
	}
	i++
	disabledExternalDiff := false
	disabledTextconv := false

	for i < len(argv) && argv[i] != "--" {
		arg := argv[i]
		switch arg {
		case "-p", "-u", "--patch", "-s", "--no-patch", "--stat",
			"--numstat", "--shortstat", "--name-only", "--name-status",
			"--check", "--summary", "--raw", "--full-index", "--no-renames",
			"--minimal", "--patience", "--histogram", "--text", "-a",
			"--no-color", "--exit-code",
			"--quiet", "-w", "-b", "--ignore-space-at-eol",
			"--ignore-cr-at-eol", "--ignore-blank-lines":
			i++
			continue
		case "--no-ext-diff":
			disabledExternalDiff = true
			i++
			continue
		case "--no-textconv":
			disabledTextconv = true
			i++
			continue
		case "-U", "--unified", "--inter-hunk-context":
			if !codexConsumeOptionValue(argv, &i) || !codexUnsignedDecimal(argv[i]) {
				return codexStaticReaderInputs{}, false
			}
			i++
			continue
		}
		switch {
		case strings.HasPrefix(arg, "-U") && len(arg) > 2:
			if !codexUnsignedDecimal(arg[2:]) {
				return codexStaticReaderInputs{}, false
			}
		case strings.HasPrefix(arg, "--unified="):
			if !codexUnsignedDecimal(strings.TrimPrefix(arg, "--unified=")) {
				return codexStaticReaderInputs{}, false
			}
		case strings.HasPrefix(arg, "--inter-hunk-context="):
			if !codexUnsignedDecimal(strings.TrimPrefix(arg, "--inter-hunk-context=")) {
				return codexStaticReaderInputs{}, false
			}
		default:
			return codexStaticReaderInputs{}, false
		}
		i++
	}
	if i >= len(argv) || argv[i] != "--" ||
		!disabledExternalDiff || !disabledTextconv {
		return codexStaticReaderInputs{}, false
	}
	for i++; i < len(argv); i++ {
		pathspec := argv[i]
		if pathspec == "" || strings.HasPrefix(pathspec, ":") ||
			strings.ContainsAny(pathspec, "*?[") ||
			!codexReaderSearchTarget(&inputs, pathspec, true) {
			return codexStaticReaderInputs{}, false
		}
	}
	return inputs, inputs.hasDataTarget
}

func codexConsumeOptionValue(argv []string, index *int) bool {
	if *index+1 >= len(argv) || argv[*index+1] == "" {
		return false
	}
	*index++
	return true
}

func codexShortOptionBundle(value, allowed string) bool {
	if value == "" {
		return false
	}
	for _, option := range value {
		if !strings.ContainsRune(allowed, option) {
			return false
		}
	}
	return true
}

func codexSignedDecimal(value string) bool {
	if len(value) < 2 || value[0] != '-' && value[0] != '+' {
		return false
	}
	for _, char := range value[1:] {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func codexExternalContentTool(toolName string) bool {
	name := strings.ToLower(strings.TrimSpace(toolName))
	canonical := strings.NewReplacer(".", "_", "-", "_", "/", "_").Replace(name)
	for _, prefix := range []string{
		"web_", "webfetch", "web_fetch", "browser_", "browser",
		"chrome_", "chrome", "http_", "http", "fetch_", "fetchurl",
		"fetch_url", "urlfetch", "url_fetch", "computer_use",
	} {
		if strings.HasPrefix(canonical, prefix) {
			return true
		}
	}
	return false
}

func codexLocalReadTool(toolName string) bool {
	name := strings.ToLower(strings.TrimSpace(toolName))
	name = strings.NewReplacer(".", "", "-", "", "_", "").Replace(name)
	switch name {
	case "read", "readfile", "fsread", "fileread", "catfile",
		"openfile", "viewfile", "getfile":
		return true
	default:
		return false
	}
}

// trustedFixtureOrGuardrailSourcePath is deliberately narrower than ordinary
// source-code recognition. Downgrading fixture/rule literals to telemetry is
// safe only for files physically proven to be inside the active workspace,
// free of symlink redirection, and explicitly identified as tests, fixtures,
// or bundled guardrail policy sources.
func trustedFixtureOrGuardrailSourcePath(path, cwd string) bool {
	return trustedFixtureOrGuardrailSourceTarget(path, cwd, false)
}

func trustedFixtureOrGuardrailSourceTarget(path, cwd string, allowDirectory bool) bool {
	relative, ok := trustedPhysicalWorkspaceRelativePath(path, cwd)
	if !ok || !fixtureOrGuardrailSourceRelativePath(relative) {
		return false
	}
	realCWD, err := filepath.EvalSymlinks(filepath.Clean(cwd))
	if err != nil || !filepath.IsAbs(realCWD) {
		return false
	}
	target := filepath.Join(realCWD, relative)
	info, err := os.Lstat(target)
	if err != nil {
		return false
	}
	if info.Mode().IsRegular() {
		return codexSingleLinkRegularFile(target, info)
	}
	if !allowDirectory || !info.IsDir() {
		return false
	}
	return codexTrustedSourceDirectory(realCWD, target)
}

// trustedCodexObserveSourceTarget is the Observe-only union of the two narrow
// physical source proofs. Each command operand is checked independently: a
// test/fixture path may use the fixture proof while an ordinary repository
// source path in the same reader chain uses the workspace-source proof. This
// does not alter Action mode's stricter whole-command classification.
func trustedCodexObserveSourcePath(path, cwd string) bool {
	return trustedCodexObserveSourceTarget(path, cwd, false)
}

func trustedCodexObserveSourceTarget(path, cwd string, allowDirectory bool) bool {
	return trustedFixtureOrGuardrailSourceTarget(path, cwd, allowDirectory) ||
		trustedObserveWorkspaceSourceTarget(path, cwd, allowDirectory)
}

func codexObserveSourceRelativePath(relative string) bool {
	return fixtureOrGuardrailSourceRelativePath(relative) ||
		observeWorkspaceSourceRelativePath(relative)
}

// trustedObserveWorkspaceSourceTarget is deliberately available only to the
// Observe-mode Codex result path. It proves a regular, repository-owned source
// artifact beneath a bounded set of conventional source/documentation roots.
// Credential stores, key material, links, devices, and unbounded trees never
// enter source scope.
func trustedObserveWorkspaceSourceTarget(path, cwd string, allowDirectory bool) bool {
	relative, ok := trustedPhysicalWorkspaceRelativePath(path, cwd)
	if !ok || !observeWorkspaceSourceRelativePath(relative) {
		return false
	}
	realCWD, err := filepath.EvalSymlinks(filepath.Clean(cwd))
	if err != nil || !filepath.IsAbs(realCWD) {
		return false
	}
	target := filepath.Join(realCWD, relative)
	info, err := os.Lstat(target)
	if err != nil {
		return false
	}
	if info.Mode().IsRegular() {
		return info.Size() >= 0 && info.Size() <= codexTrustedSourceTreeMaxBytes &&
			codexSingleLinkRegularFile(target, info)
	}
	if !allowDirectory || !info.IsDir() {
		return false
	}
	return codexObserveSourceDirectory(realCWD, target)
}

func observeWorkspaceSourceRelativePath(relative string) bool {
	relative = strings.ToLower(filepath.ToSlash(relative))
	relative = strings.Trim(relative, "/")
	if relative == "" {
		return false
	}
	parts := strings.Split(relative, "/")
	switch parts[0] {
	case "internal", "policies", "docs", "cmd", "pkg", "src", "lib", "app",
		"scripts", "test", "tests", "testdata", "fixtures", "examples":
	default:
		return false
	}
	for _, part := range parts {
		switch part {
		case ".git", ".ssh", ".aws", ".gnupg", ".kube", ".docker":
			return false
		}
	}
	base := parts[len(parts)-1]
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		return false
	}
	switch base {
	case "credentials", "credentials.json", "auth.json", "token", ".netrc",
		".npmrc", ".pypirc", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519":
		return false
	}
	switch strings.ToLower(filepath.Ext(base)) {
	case ".env", ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore":
		return false
	}
	if strings.HasPrefix(base, "secrets.") &&
		!fixtureOrGuardrailSourceRelativePath(relative) {
		return false
	}
	return true
}

func codexObserveSourceDirectory(realCWD, root string) bool {
	entries := 0
	var totalBytes int64
	walkErr := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry == nil {
			return errCodexUntrustedSourceTree
		}
		entries++
		if entries > codexTrustedSourceTreeMaxEntries {
			return errCodexUntrustedSourceTree
		}
		rootRelative, err := filepath.Rel(root, path)
		if err != nil || rootRelative == ".." ||
			strings.HasPrefix(rootRelative, ".."+string(filepath.Separator)) {
			return errCodexUntrustedSourceTree
		}
		if rootRelative != "." &&
			strings.Count(filepath.ToSlash(rootRelative), "/")+1 > codexTrustedSourceTreeMaxDepth {
			return errCodexUntrustedSourceTree
		}
		workspaceRelative, err := filepath.Rel(realCWD, path)
		if err != nil || workspaceRelative == "." || workspaceRelative == ".." ||
			strings.HasPrefix(workspaceRelative, ".."+string(filepath.Separator)) ||
			!observeWorkspaceSourceRelativePath(workspaceRelative) {
			return errCodexUntrustedSourceTree
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errCodexUntrustedSourceTree
		}
		info, err := entry.Info()
		if err != nil {
			return errCodexUntrustedSourceTree
		}
		if info.IsDir() {
			return nil
		}
		if !codexSingleLinkRegularFile(path, info) || info.Size() < 0 ||
			info.Size() > codexTrustedSourceTreeMaxBytes-totalBytes {
			return errCodexUntrustedSourceTree
		}
		totalBytes += info.Size()
		return nil
	})
	return walkErr == nil
}

// codexTrustedSourceDirectory proves a recursive reader's complete physical
// input set. Symlinks are rejected rather than skipped because search-tool
// follow semantics vary; regular descendants must have exactly one link so a
// live file cannot be laundered into a fixture tree through a hard link. Only
// directories and bounded, single-link regular files are accepted, excluding
// FIFOs, sockets, devices, and other process-controlled sources.
func codexTrustedSourceDirectory(realCWD, root string) bool {
	entries := 0
	var totalBytes int64
	walkErr := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry == nil {
			return errCodexUntrustedSourceTree
		}
		entries++
		if entries > codexTrustedSourceTreeMaxEntries {
			return errCodexUntrustedSourceTree
		}

		rootRelative, err := filepath.Rel(root, path)
		if err != nil || rootRelative == ".." ||
			strings.HasPrefix(rootRelative, ".."+string(filepath.Separator)) {
			return errCodexUntrustedSourceTree
		}
		if rootRelative != "." &&
			strings.Count(filepath.ToSlash(rootRelative), "/")+1 > codexTrustedSourceTreeMaxDepth {
			return errCodexUntrustedSourceTree
		}

		workspaceRelative, err := filepath.Rel(realCWD, path)
		if err != nil || workspaceRelative == "." || workspaceRelative == ".." ||
			strings.HasPrefix(workspaceRelative, ".."+string(filepath.Separator)) ||
			!fixtureOrGuardrailSourceRelativePath(workspaceRelative) {
			return errCodexUntrustedSourceTree
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errCodexUntrustedSourceTree
		}
		info, err := entry.Info()
		if err != nil {
			return errCodexUntrustedSourceTree
		}
		if info.IsDir() {
			return nil
		}
		if !codexSingleLinkRegularFile(path, info) || info.Size() < 0 ||
			info.Size() > codexTrustedSourceTreeMaxBytes-totalBytes {
			return errCodexUntrustedSourceTree
		}
		totalBytes += info.Size()
		return nil
	})
	return walkErr == nil
}

func codexSingleLinkRegularFile(path string, info os.FileInfo) bool {
	return path != "" && info != nil && info.Mode().IsRegular() &&
		codexSourceFileHasSingleLink(path, info)
}

func fixtureOrGuardrailSourcePathLexical(path, cwd string) bool {
	relative, ok := trustedWorkspaceRelativePath(path, cwd)
	if !ok {
		return false
	}
	return fixtureOrGuardrailSourceRelativePath(relative)
}

func fixtureOrGuardrailSourceRelativePath(relative string) bool {
	relative = strings.ToLower(filepath.ToSlash(relative))
	base := filepath.Base(relative)
	padded := "/" + strings.Trim(relative, "/") + "/"
	for _, segment := range []string{
		"/test/", "/tests/", "/testdata/", "/fixtures/", "/__tests__/",
	} {
		if strings.Contains(padded, segment) {
			return true
		}
	}
	if strings.Contains(base, "_test.") || strings.HasSuffix(base, ".test") {
		return true
	}
	if relative == "internal/gateway/rules_catalog_generated.go" {
		return true
	}
	return strings.HasPrefix(relative, "policies/guardrail/") ||
		relative == "policies/guardrail"
}

func trustedPhysicalWorkspaceRelativePath(path, cwd string) (string, bool) {
	relative, ok := trustedWorkspaceRelativePath(path, cwd)
	if !ok {
		return "", false
	}
	realCWD, err := filepath.EvalSymlinks(filepath.Clean(cwd))
	if err != nil || !filepath.IsAbs(realCWD) {
		return "", false
	}
	realPath, err := filepath.EvalSymlinks(filepath.Join(filepath.Clean(cwd), relative))
	if err != nil || !filepath.IsAbs(realPath) {
		return "", false
	}
	expected := filepath.Clean(filepath.Join(realCWD, relative))
	if filepath.Clean(realPath) != expected {
		return "", false
	}
	physicalRelative, err := filepath.Rel(realCWD, realPath)
	if err != nil || physicalRelative == "." || physicalRelative == ".." ||
		strings.HasPrefix(physicalRelative, ".."+string(filepath.Separator)) {
		return "", false
	}
	return physicalRelative, true
}

func trustedWorkspaceRelativePath(path, cwd string) (string, bool) {
	if path == "" || cwd == "" || !filepath.IsAbs(cwd) {
		return "", false
	}
	cwd = filepath.Clean(cwd)
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}
	path = filepath.Clean(path)
	relative, err := filepath.Rel(cwd, path)
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", false
	}
	return relative, true
}

func (a *APIServer) scanCodexChangedFiles(ctx context.Context, req codexHookRequest) *ToolInspectVerdict {
	targets := a.codexStopTargets(ctx, req)
	if len(targets) == 0 {
		return &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	}

	rulesDir := ""
	if a.scannerCfg != nil {
		rulesDir = a.scannerCfg.Scanners.CodeGuard
	}
	cg := scanner.NewCodeGuardScanner(rulesDir)
	maxSeverity := scanner.SeverityInfo
	findings := []string{}
	for _, target := range targets {
		result, err := cg.Scan(ctx, target)
		if err != nil {
			continue
		}
		if a.logger != nil {
			_ = a.logger.LogScanWithCorrelation(ctx, result, "", ScanCorrelationFromContext(ctx))
		}
		if result.MaxSeverity() != scanner.SeverityInfo && scanner.CompareSeverity(result.MaxSeverity(), maxSeverity) > 0 {
			maxSeverity = result.MaxSeverity()
		}
		for _, f := range result.Findings {
			findings = append(findings, firstNonEmpty(f.RuleID, f.ID))
			if len(findings) >= 20 {
				break
			}
		}
	}
	if len(findings) == 0 {
		return &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	}
	action := "alert"
	if maxSeverity == scanner.SeverityCritical || maxSeverity == scanner.SeverityHigh {
		action = "block"
	}
	return &ToolInspectVerdict{
		Action:   action,
		Severity: string(maxSeverity),
		Reason:   fmt.Sprintf("CodeGuard found %d finding(s) in Codex changed files", len(findings)),
		Findings: findings,
	}
}

func (a *APIServer) codexStopTargets(ctx context.Context, req codexHookRequest) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if !filepath.IsAbs(p) && req.CWD != "" {
			p = filepath.Join(req.CWD, p)
		}
		if seen[p] {
			return
		}
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			seen[p] = true
			out = append(out, p)
		}
	}
	if a.scannerCfg != nil {
		for _, p := range a.scannerCfg.ConnectorHookConfig("codex").ScanPaths {
			add(p)
		}
	}
	changedFiles, gitErr := gitChangedFiles(ctx, req.CWD)
	if gitErr != nil {
		fmt.Fprintf(os.Stderr, "[codex-hook] WARNING: git scan failed: %v — scanning configured paths only\n", gitErr)
	}
	for _, p := range changedFiles {
		add(p)
	}
	if len(out) > 200 {
		return out[:200]
	}
	return out
}

func gitChangedFiles(ctx context.Context, cwd string) ([]string, error) {
	safeCwd, err := validateGitCwd(cwd)
	if err != nil {
		return nil, err
	}
	cmdCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var errs []error
	files, err := runGitList(cmdCtx, safeCwd, "diff", "--name-only", "--diff-filter=ACMRT", "HEAD", "--")
	if err != nil {
		errs = append(errs, err)
	}
	extra, err := runGitList(cmdCtx, safeCwd, "ls-files", "--others", "--exclude-standard")
	if err != nil {
		errs = append(errs, err)
	}
	files = append(files, extra...)

	if len(errs) > 0 && len(files) == 0 {
		return nil, fmt.Errorf("git commands failed: %v", errs)
	}
	return files, nil
}

// sanitizeHookCWD resolves symlinks and ensures the cwd is an absolute,
// existing directory. Returns the canonicalized path, or empty string if
// the input is blank or invalid. Used at hook handler entry to sanitize
// the caller-supplied cwd before it flows into filepath.Join / cmd.Dir.
func sanitizeHookCWD(cwd string) string {
	s := strings.TrimSpace(cwd)
	if s == "" {
		return ""
	}
	if !filepath.IsAbs(s) {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(s)
	if err != nil {
		return ""
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return ""
	}
	return resolved
}

// validateGitCwd resolves symlinks and ensures the cwd is a real directory.
// Returns the canonicalized path or an error if validation fails.
func validateGitCwd(cwd string) (string, error) {
	if strings.TrimSpace(cwd) == "" {
		return "", fmt.Errorf("empty cwd")
	}
	resolved, err := filepath.EvalSymlinks(cwd)
	if err != nil {
		return "", fmt.Errorf("resolve cwd %s: %w", cwd, err)
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("cwd is not a directory: %s", resolved)
	}
	return resolved, nil
}

// safeGitEnv returns environment variables that prevent git from executing
// attacker-controlled config hooks (core.fsmonitor, core.hooksPath, etc.)
// by disabling system/global config and pointing HOME to a safe empty dir.
//
// Avarice F-3347: the legacy implementation only disabled system and
// global config. Repository-local `.git/config` remained active, so a
// hostile workspace could set `core.fsmonitor`, `core.hooksPath`,
// `protocol.<x>.allow=user`, etc. and have git execute attacker
// commands during routine `git diff` / `git ls-files` calls. We use
// GIT_CONFIG_COUNT/KEY/VALUE to provide a *replacement* config layer
// that overrides anything set in the repository, and unset
// GIT_CONFIG_PARAMETERS so a poisoned parent env can't add more.
func safeGitEnv() []string {
	// (key, value) pairs that neutralise the most dangerous repo-
	// local config knobs. Note: we cannot fully prevent git from
	// reading `.git/config`, but per `gitconfig(5)`,
	// GIT_CONFIG_KEY_<n>/VALUE_<n> entries override repo-local
	// values so any malicious setting becomes a no-op for the
	// hooks/diff helpers we run.
	overrides := []string{
		"core.fsmonitor", "false",
		"core.fsmonitorhookversion", "1",
		"core.hooksPath", "/dev/null",
		"core.sshCommand", "false",
		"core.gitProxy", "false",
		"core.editor", "/bin/false",
		"core.pager", "cat",
		"diff.external", "false",
		"diff.tool", "false",
		"protocol.allow", "never",
		"protocol.file.allow", "never",
		"protocol.ext.allow", "never",
		"uploadpack.allowFilter", "false",
		"uploadpack.allowAnySHA1InWant", "false",
		"safe.directory", "*",
	}
	env := append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"HOME="+os.TempDir(),
		// Disable any pre-existing GIT_CONFIG_PARAMETERS override
		// inherited from a parent process.
		"GIT_CONFIG_PARAMETERS=",
	)
	pairs := 0
	for i := 0; i+1 < len(overrides); i += 2 {
		env = append(env,
			fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", pairs, overrides[i]),
			fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", pairs, overrides[i+1]),
		)
		pairs++
	}
	env = append(env, fmt.Sprintf("GIT_CONFIG_COUNT=%d", pairs))
	return env
}

func runGitList(ctx context.Context, cwd string, args ...string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = cwd
	cmd.Env = safeGitEnv()

	// Bound stdout via io.LimitReader so a monorepo with many
	// millions of tracked files (or a hostile worktree manufactured
	// to exhaust gateway memory) cannot OOM the sidecar. We read up
	// to runGitListMaxBytes+1 — the extra byte tells us when the cap
	// was breached so we can fail loudly instead of returning a
	// silently-truncated file list (which would mis-report changed
	// files and miss legitimate guardrail signals).
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("git %v in %s: stdout pipe: %w", args, cwd, err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("git %v in %s: start: %w", args, cwd, err)
	}
	var buf bytes.Buffer
	if _, copyErr := io.CopyN(&buf, stdout, int64(runGitListMaxBytes)+1); copyErr != nil && copyErr != io.EOF {
		// Drain remaining stdout / wait so the child does not get
		// SIGPIPE before we report the underlying error. We
		// intentionally ignore the wait error here because the read
		// failure is the actionable signal.
		_, _ = io.Copy(io.Discard, stdout)
		_ = cmd.Wait()
		return nil, fmt.Errorf("git %v in %s: read stdout: %w", args, cwd, copyErr)
	}
	if buf.Len() > runGitListMaxBytes {
		_, _ = io.Copy(io.Discard, stdout)
		_ = cmd.Wait()
		return nil, fmt.Errorf("git %v in %s: stdout exceeded %d bytes", args, cwd, runGitListMaxBytes)
	}
	if waitErr := cmd.Wait(); waitErr != nil {
		return nil, fmt.Errorf("git %v in %s: %w", args, cwd, waitErr)
	}

	lines := strings.Split(buf.String(), "\n")
	ret := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			ret = append(ret, line)
		}
	}
	return ret, nil
}

func (a *APIServer) scanCodexComponents(ctx context.Context, req codexHookRequest) int {
	if a.scannerCfg == nil {
		return 0
	}
	if !req.ScanComponents && !a.codexComponentScanDue() {
		return 0
	}
	targets := codexComponentTargets(req.CWD)
	count := 0
	for component, paths := range targets {
		for _, p := range paths {
			if _, err := os.Stat(p); err != nil {
				continue
			}
			if a.scanCodexComponent(ctx, component, p) {
				count++
			}
		}
	}
	return count
}

func (a *APIServer) codexComponentScanDue() bool {
	interval := 60 * time.Minute
	if a.scannerCfg != nil && a.scannerCfg.ConnectorHookConfig("codex").ComponentScanIntervalMinutes > 0 {
		interval = time.Duration(a.scannerCfg.ConnectorHookConfig("codex").ComponentScanIntervalMinutes) * time.Minute
	}
	a.codexMu.Lock()
	defer a.codexMu.Unlock()
	if !a.codexLastComponentScan.IsZero() && time.Since(a.codexLastComponentScan) < interval {
		return false
	}
	a.codexLastComponentScan = time.Now()
	return true
}

// codexComponentTargets returns expanded, deduplicated targets for runtime
// scanning. This is the detailed counterpart of
// CodexConnector.ComponentTargets() (which returns structural parent
// directories for the fsnotify watcher and CLI). Changes to the directory
// layout should be reflected in both places.
func codexComponentTargets(cwd string) map[string][]string {
	targets := map[string][]string{
		"skill":  {},
		"plugin": {},
		"mcp":    {},
	}

	home, err := os.UserHomeDir()
	if err == nil {
		codexHome := filepath.Join(home, ".codex")
		targets["skill"] = append(targets["skill"], childDirs(filepath.Join(codexHome, "skills"))...)
		targets["plugin"] = append(targets["plugin"],
			childDirs(filepath.Join(codexHome, "plugins"))...)
		targets["plugin"] = append(targets["plugin"],
			childDirs(filepath.Join(codexHome, "plugins", "cache"))...)
		targets["mcp"] = append(targets["mcp"], existingFiles(filepath.Join(codexHome, "config.toml"))...)
	}

	for _, root := range workspaceCodexRoots(cwd) {
		targets["skill"] = append(targets["skill"],
			childDirs(filepath.Join(root, ".codex", "skills"))...)
		targets["skill"] = append(targets["skill"],
			childDirs(filepath.Join(root, "skills"))...)
		targets["plugin"] = append(targets["plugin"],
			childDirs(filepath.Join(root, ".codex", "plugins"))...)
		targets["plugin"] = append(targets["plugin"],
			childDirs(filepath.Join(root, ".codex", "plugins", "cache"))...)
		targets["plugin"] = append(targets["plugin"],
			childDirs(filepath.Join(root, ".agents", "plugins"))...)
		targets["mcp"] = append(targets["mcp"],
			existingFiles(filepath.Join(root, ".codex", "config.toml"), filepath.Join(root, ".mcp.json"))...)
	}
	for k, paths := range targets {
		targets[k] = uniqueExistingPaths(paths)
	}
	return targets
}

func workspaceCodexRoots(cwd string) []string {
	roots := []string{}
	if strings.TrimSpace(cwd) != "" {
		roots = append(roots, cwd)
		if root := gitRootForCWD(cwd); root != "" {
			roots = append(roots, root)
		}
	}
	return uniqueExistingDirs(roots)
}

func gitRootForCWD(cwd string) string {
	safeCwd, err := validateGitCwd(cwd)
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "--show-toplevel")
	cmd.Dir = safeCwd
	cmd.Env = safeGitEnv()
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func childDirs(root string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			out = append(out, filepath.Join(root, entry.Name()))
		}
	}
	return out
}

func existingFiles(paths ...string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func uniqueExistingDirs(paths []string) []string {
	out := make([]string, 0, len(paths))
	seen := map[string]bool{}
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func uniqueExistingPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	seen := map[string]bool{}
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func (a *APIServer) scanCodexComponent(ctx context.Context, component, target string) bool {
	if a.scannerCfg == nil {
		return false
	}
	var (
		result *scanner.ScanResult
		err    error
	)
	scanCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	switch component {
	case "skill":
		ss := scanner.NewSkillScannerFromLLM(
			a.scannerCfg.Scanners.SkillScanner,
			a.scannerCfg.ResolveLLM("scanners.skill"),
			a.scannerCfg.CiscoAIDefense,
		)
		result, err = ss.Scan(scanCtx, target)
	case "plugin":
		ps := scanner.NewPluginScanner(a.scannerCfg.Scanners.PluginScanner)
		result, err = ps.Scan(scanCtx, target)
	case "mcp":
		ms := scanner.NewMCPScannerFromLLM(
			a.scannerCfg.Scanners.MCPScanner,
			a.scannerCfg.ResolveLLM("scanners.mcp"),
			a.scannerCfg.CiscoAIDefense,
		)
		result, err = ms.Scan(scanCtx, target)
	}
	if err != nil {
		return false
	}
	if result != nil && a.logger != nil {
		_ = a.logger.LogScanWithCorrelation(ctx, result, "", ScanCorrelationFromContext(ctx))
	}
	return true
}
