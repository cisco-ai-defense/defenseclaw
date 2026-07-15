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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/notifier"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

type claudeCodeHookRequest struct {
	HookEventName        string                 `json:"hook_event_name"`
	SessionID            string                 `json:"session_id,omitempty"`
	TurnID               string                 `json:"turn_id,omitempty"`
	MessageID            string                 `json:"message_id,omitempty"`
	TranscriptPath       string                 `json:"transcript_path,omitempty"`
	CWD                  string                 `json:"cwd,omitempty"`
	PermissionMode       string                 `json:"permission_mode,omitempty"`
	Model                string                 `json:"model,omitempty"`
	Source               string                 `json:"source,omitempty"`
	AgentID              string                 `json:"agent_id,omitempty"`
	AgentType            string                 `json:"agent_type,omitempty"`
	OldCWD               string                 `json:"old_cwd,omitempty"`
	NewCWD               string                 `json:"new_cwd,omitempty"`
	ToolName             string                 `json:"tool_name,omitempty"`
	ToolUseID            string                 `json:"tool_use_id,omitempty"`
	ToolInput            map[string]interface{} `json:"tool_input,omitempty"`
	ToolResponse         interface{}            `json:"tool_response,omitempty"`
	ToolCalls            interface{}            `json:"tool_calls,omitempty"`
	Prompt               string                 `json:"prompt,omitempty"`
	ExpansionType        string                 `json:"expansion_type,omitempty"`
	CommandName          string                 `json:"command_name,omitempty"`
	CommandArgs          string                 `json:"command_args,omitempty"`
	CommandSource        string                 `json:"command_source,omitempty"`
	StopHookActive       bool                   `json:"stop_hook_active,omitempty"`
	LastAssistantMessage string                 `json:"last_assistant_message,omitempty"`
	Error                string                 `json:"error,omitempty"`
	ErrorDetails         string                 `json:"error_details,omitempty"`
	Message              string                 `json:"message,omitempty"`
	Delta                string                 `json:"delta,omitempty"`
	DisplayIndex         int                    `json:"index,omitempty"`
	DisplayFinal         bool                   `json:"final,omitempty"`
	Title                string                 `json:"title,omitempty"`
	FilePath             string                 `json:"file_path,omitempty"`
	LoadReason           string                 `json:"load_reason,omitempty"`
	MemoryType           string                 `json:"memory_type,omitempty"`
	MCPServerName        string                 `json:"mcp_server_name,omitempty"`
	ElicitationAction    string                 `json:"action,omitempty"`
	URL                  string                 `json:"url,omitempty"`
	ScanComponents       bool                   `json:"scan_components,omitempty"`
	Bridge               map[string]interface{} `json:"bridge,omitempty"`
	Payload              map[string]interface{} `json:"-"`
}

type claudeCodeHookResponse struct {
	Action            string                 `json:"action"`
	RawAction         string                 `json:"raw_action,omitempty"`
	Severity          string                 `json:"severity"`
	Reason            string                 `json:"reason,omitempty"`
	Findings          []string               `json:"findings,omitempty"`
	Mode              string                 `json:"mode"`
	WouldBlock        bool                   `json:"would_block"`
	AdditionalContext string                 `json:"additional_context,omitempty"`
	ClaudeCodeOutput  map[string]interface{} `json:"claude_code_output,omitempty"`
	// EvaluationID joins this hook response to the matching audit
	// row + per-finding scan_findings rows. Additive — older
	// connector hook scripts ignore the field.
	EvaluationID string `json:"evaluation_id,omitempty"`
	// RuleIDs are the top detection rule_ids that drove this
	// verdict (capped at 8). Lets operators correlate a block
	// without joining against scan_findings. Additive.
	RuleIDs []string `json:"rule_ids,omitempty"`
	// RedactionEnabled carries the cloud-controlled per-inspection
	// redaction directive back through the unified dispatch so
	// finalizeAgentHook can honor it on the hook_decision event +
	// audit row. Never serialized on the hook response wire.
	RedactionEnabled *bool  `json:"-"`
	SourceReason     string `json:"-"`
}

// Claude Code hook traffic flows through the unified pipeline at
// handleAgentHook("claudecode"); the profile-runtime registry invokes
// the connector-specific evaluator kept below. The pipeline's shared
// concerns — audit envelope refresh, dispatch metric, dedup, trace
// propagation, and v8 observability emissions — live in exactly one place
// (handleAgentHook) so per-connector handlers cannot drift apart on
// any of those signals. The evaluator stamps the unified-pipeline
// correlation keys (resp.EvaluationID / resp.RuleIDs) on its return
// value so downstream tooling and the audit envelope receive them.

func (a *APIServer) evaluateClaudeCodeHook(ctx context.Context, req claudeCodeHookRequest) claudeCodeHookResponse {
	mode := a.claudeCodeMode()
	if a.scannerCfg != nil && !a.claudeCodeEnabled() {
		return claudeCodeResponseFor(req, "allow", "allow", "NONE", "", nil, mode, false)
	}
	t0 := time.Now()

	verdict := &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	var assetDecisions []runtimeAssetDecision
	switch req.HookEventName {
	case "SessionStart":
		if req.ScanComponents || (a.scannerCfg != nil && a.scannerCfg.ConnectorHookConfig("claudecode").ScanOnSessionStart) {
			count := a.scanClaudeCodeComponents(ctx, req)
			if count > 0 {
				verdict = &ToolInspectVerdict{
					Action:   "allow",
					Severity: "INFO",
					Reason:   fmt.Sprintf("scanned %d Claude Code component(s)", count),
					Findings: []string{"CLAUDE-CODE-COMPONENT-SCAN"},
				}
			}
		}
	case "UserPromptSubmit", "UserPromptExpansion":
		verdict = a.inspectMessageContent(ctx, &ToolInspectRequest{Tool: "message", Content: claudeCodePromptContent(req), Direction: "prompt", Connector: "claudecode"})
		if req.HookEventName == "UserPromptExpansion" {
			assetDecisions = append(assetDecisions, a.claudeCodePromptExpansionAssetDecisions(ctx, req)...)
		}
	case "PreToolUse", "PermissionRequest", "PermissionDenied":
		verdict = a.inspectToolPolicyCtx(ctx, &ToolInspectRequest{Tool: claudeCodeToolName(req), Args: claudeCodeToolArgs(req), Direction: "tool_call", Connector: "claudecode", MCPServerName: req.MCPServerName})
		if decision, matched := a.claudeCodeMCPAssetDecision(ctx, req); matched {
			assetDecisions = append(assetDecisions, runtimeAssetDecision{targetType: "mcp", decision: decision})
		}
		if decision, matched := a.claudeCodeSkillAssetDecision(ctx, req); matched {
			assetDecisions = append(assetDecisions, runtimeAssetDecision{targetType: "skill", decision: decision})
		}
	case "PostToolUse", "PostToolUseFailure", "PostToolBatch":
		verdict = a.inspectMessageContent(ctx, &ToolInspectRequest{Tool: "message", Content: claudeCodeToolOutput(req), Direction: "tool_result", Connector: "claudecode"})
		if decision, matched := a.claudeCodeMCPAssetDecision(ctx, req); matched {
			assetDecisions = append(assetDecisions, runtimeAssetDecision{targetType: "mcp", decision: decision})
		}
		if decision, matched := a.claudeCodeSkillAssetDecision(ctx, req); matched {
			assetDecisions = append(assetDecisions, runtimeAssetDecision{targetType: "skill", decision: decision})
		}
	case "Stop", "SubagentStop", "SessionEnd":
		if !req.StopHookActive && a.scannerCfg != nil && a.scannerCfg.ConnectorHookConfig("claudecode").ScanOnStop {
			verdict = a.scanClaudeCodeChangedFiles(ctx, req)
		}
	case "InstructionsLoaded", "ConfigChange", "FileChanged":
		verdict = a.scanClaudeCodeEventFile(ctx, req)
		if verdict == nil {
			verdict = a.inspectMessageContent(ctx, &ToolInspectRequest{Tool: "message", Content: claudeCodeEventContent(req), Direction: "prompt", Connector: "claudecode"})
		}
	case "TaskCreated", "TaskCompleted", "TeammateIdle",
		"PreCompact", "PostCompact", "Elicitation", "ElicitationResult", "Notification":
		verdict = a.inspectMessageContent(ctx, &ToolInspectRequest{Tool: "message", Content: claudeCodeEventContent(req), Direction: "prompt", Connector: "claudecode"})
	}

	// Inject the cloud-controlled per-inspection redaction directive
	// onto the context so the downstream emit choke points and the OS
	// toast honor it (managed_enterprise only; no-op otherwise).
	ctx = withRedactionDecision(ctx, verdict.RedactionEnabled)

	rawAction := normalizeCodexAction(verdict.Action)
	rawActionBeforeAssets := rawAction
	action := rawAction
	wouldBlock := rawAction == "block" && mode != "action"
	if rawAction == "block" && !claudeCodeCanEnforce(req) {
		action = "allow"
		wouldBlock = true
	} else if mode != "action" && rawAction == "block" {
		action = "allow"
	}
	if mode != "action" && (rawAction == "alert" || rawAction == "confirm") {
		action = "allow"
	}
	if mode == "action" && rawAction == "confirm" && req.HookEventName != "PreToolUse" {
		action = "alert"
	}
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
	}
	// Fan the rule-level findings through the unified runtime
	// finding pipeline so SIEM sees one EventScanFinding per
	// matched rule and the correlator gets a chance to upgrade
	// the verdict on multi-step attack flows. scanner="hook-rules".
	// Done before dispatchClaudeCodeHookNotification so the OS toast
	// can carry the same evaluation_id + rule_ids that the audit
	// row + HTTP response will surface.
	evalCtx := a.emitHookRuleFindings(ctx, "claudecode", req.HookEventName, verdict,
		hookTargetTypeForEvent(req.HookEventName), time.Since(t0))
	if !hookNotificationCoveredByAssetPolicy(rawActionBeforeAssets, assetDecisions) {
		a.dispatchClaudeCodeHookNotification(req, action, rawAction, verdict.Severity, verdict.Reason, wouldBlock, evalCtx,
			sinkPolicyFor(ctx, verdict.RedactionEnabled))
	}
	resp := claudeCodeResponseFor(req, action, rawAction, verdict.Severity, verdict.Reason, verdict.Findings, mode, wouldBlock)
	// Stamp the unified-pipeline correlation keys so the agent-hook
	// dispatch wrapper (claudeCodeResponseToAgentHookResponse) and
	// the audit envelope (HookAuditEnvelope.EvaluationID / RuleIDs)
	// both see them without a second pass.
	resp.EvaluationID = evalCtx.EvaluationID
	resp.RuleIDs = evalCtx.RuleIDs
	resp.RedactionEnabled = verdict.RedactionEnabled
	return resp
}

// dispatchClaudeCodeHookNotification fires a user-session OS toast
// for any non-allow verdict the hook produced. Routing is:
//
//   - action=="block"            → notifier.OnBlock
//   - rawAction=="block" and we did not actually enforce (observe
//     mode, or the hook event is not enforceable) → OnWouldBlock
//   - rawAction=="confirm"       → OnApprovalPending
//
// All callers receive the same audit-shaped subtitle (source +
// severity + connector + hook event) so operators can tell the
// surface from the toast without opening the audit log. The reason
// is run through redaction.ForSinkReason before display so a
// regex-match verdict carrying echoed user content (PII, secrets)
// does not land verbatim on the screen — this matches how proxy.go
// and hilt.go feed the same dispatcher.
// dispatchClaudeCodeHookNotification follows the same routing
// contract documented on dispatchAgentHookNotification. The
// rawAction=="confirm" && action!="confirm" branch covers observe
// mode (claudecode's PreToolUse response is permissionDecision=allow
// in observe mode, so no chat ask is issued) — those toasts go
// through OnWouldBlock with WouldAsk=true so a single
// notifications.block_would_block=false silences all observe-mode
// noise without affecting real native asks.
func (a *APIServer) dispatchClaudeCodeHookNotification(req claudeCodeHookRequest, action, rawAction, severity, reason string, wouldBlock bool, evalCtx hookEvaluationContext, policy ...redaction.SinkPolicy) {
	if a == nil || a.notifier == nil {
		return
	}
	target := strings.TrimSpace(req.ToolName)
	if target == "" {
		target = req.HookEventName
	}
	// Honor the cloud-controlled per-inspection redaction policy
	// (all-sinks scope, managed_enterprise only) when a caller passes
	// one; otherwise default to the historical ForSinkReason behavior.
	safeReason := redaction.ReasonForSink(reason, notificationSinkPolicy(policy))
	base := notifier.BlockEvent{
		Source:       notifier.SourceHook,
		Target:       target,
		Reason:       safeReason,
		Severity:     severity,
		Connector:    "claudecode",
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
			Connector:    "claudecode",
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

// claudeCodeEnabled returns true when the claude-code hook handler
// should evaluate inspection rules. Selecting the claudecode connector
// is a sufficient opt-in — no second `claude_code.enabled: true` is
// needed — because the connector's Setup() has already installed the
// hooks into ~/.claude/settings.json. An explicit claude_code.enabled
// flag still wins for operators who run claudecode alongside a
// different selected connector (e.g. test harnesses).
func (a *APIServer) claudeCodeEnabled() bool {
	if a.scannerCfg == nil {
		return false
	}
	// Per-connector explicit disable wins over every enable signal below:
	// `guardrail disable --connector claudecode` yields allow-without-scan
	// even though claudecode stays in guardrail.connectors (policy retained
	// for re-enable). Defense-in-depth alongside the boot-loop teardown.
	// EffectiveEnabled defaults to true ⇒ no-op for single-connector
	// installs and any connector never explicitly disabled.
	if a.scannerCfg.ManualConnectorConfigured("claudecode") && !a.scannerCfg.Guardrail.EffectiveEnabled("claudecode") {
		return false
	}
	hookCfg := a.scannerCfg.ConnectorHookConfig("claudecode")
	if hookCfg.Enabled {
		return true
	}
	if a.health != nil && a.health.HasConnectorSource("claudecode", "automatic") && a.scannerCfg.ApplicationProtection.EffectiveEnabled("claudecode") {
		return true
	}
	// Multi-connector: membership in guardrail.connectors opts claudecode
	// in even when it is not the singular primary (no-op for single).
	if a.scannerCfg.Guardrail.HasConnector("claudecode") {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(a.scannerCfg.Guardrail.Connector), "claudecode")
}

func (a *APIServer) claudeCodeMode() string {
	mode := "observe"
	if a.scannerCfg != nil {
		hookCfg := a.scannerCfg.ConnectorHookConfig("claudecode")
		mode = strings.TrimSpace(hookCfg.Mode)
		if mode == "" || mode == "inherit" {
			// Per-connector guardrail override wins over global mode.
			mode = strings.TrimSpace(a.scannerCfg.EffectiveGuardrailModeForConnector("claudecode"))
		}
	}
	return normalizeAgentHookMode(mode)
}

func claudeCodeResponseFor(req claudeCodeHookRequest, action, rawAction, severity, reason string, findings []string, mode string, wouldBlock bool) claudeCodeHookResponse {
	if severity == "" {
		severity = "NONE"
	}
	if action == "" {
		action = "allow"
	}
	if rawAction == "" {
		rawAction = action
	}
	safeReason := redaction.ReasonForAgent(reason)
	additional := claudeCodeAdditionalContext(rawAction, severity, safeReason, wouldBlock)
	resp := claudeCodeHookResponse{
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
	resp.ClaudeCodeOutput = claudeCodeOutput(req, action, rawAction, safeReason, additional)
	return resp
}

func claudeCodeCanEnforce(req claudeCodeHookRequest) bool {
	// Claude Code reports ConfigChange for managed policy updates too, but
	// explicitly ignores blocking decisions for policy_settings. Treating that
	// response as enforced would create false-positive block telemetry.
	if req.HookEventName == "ConfigChange" && strings.EqualFold(strings.TrimSpace(req.Source), "policy_settings") {
		return false
	}

	switch req.HookEventName {
	case "UserPromptSubmit", "UserPromptExpansion", "PreToolUse", "PermissionRequest",
		"PostToolBatch", "TaskCreated", "TaskCompleted", "Stop", "SubagentStop", "TeammateIdle",
		"ConfigChange", "PreCompact", "Elicitation", "ElicitationResult":
		return true
	default:
		return false
	}
}

func claudeCodeOutput(req claudeCodeHookRequest, action, rawAction, reason, additional string) map[string]interface{} {
	event := req.HookEventName
	if action == "confirm" && event == "PreToolUse" {
		return map[string]interface{}{"hookSpecificOutput": map[string]interface{}{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "ask",
			"permissionDecisionReason": reasonOrDefaultClaudeCode(reason),
		}}
	}
	if action == "block" {
		switch event {
		case "PreToolUse":
			return map[string]interface{}{"hookSpecificOutput": map[string]interface{}{
				"hookEventName":            "PreToolUse",
				"permissionDecision":       "deny",
				"permissionDecisionReason": reasonOrDefaultClaudeCode(reason),
			}}
		case "PermissionRequest":
			return map[string]interface{}{"hookSpecificOutput": map[string]interface{}{
				"hookEventName": "PermissionRequest",
				"decision": map[string]interface{}{
					"behavior": "deny",
					"message":  reasonOrDefaultClaudeCode(reason),
				},
			}}
		case "TaskCreated", "TaskCompleted", "TeammateIdle":
			return map[string]interface{}{"continue": false, "stopReason": reasonOrDefaultClaudeCode(reason)}
		case "Elicitation":
			return map[string]interface{}{"hookSpecificOutput": map[string]interface{}{
				"hookEventName": "Elicitation",
				"action":        "decline",
				"content":       map[string]interface{}{},
			}}
		case "ElicitationResult":
			return map[string]interface{}{"hookSpecificOutput": map[string]interface{}{
				"hookEventName": "ElicitationResult",
				"action":        "decline",
				"content":       map[string]interface{}{},
			}}
		default:
			return map[string]interface{}{"decision": "block", "reason": reasonOrDefaultClaudeCode(reason)}
		}
	}
	if event == "CwdChanged" || event == "FileChanged" {
		out := map[string]interface{}{"watchPaths": claudeCodeWatchPaths(req)}
		if additional != "" {
			out["systemMessage"] = additional
		}
		return out
	}
	if additional == "" {
		return nil
	}
	switch event {
	case "SessionStart", "UserPromptSubmit", "UserPromptExpansion", "PostToolUse", "PostToolUseFailure",
		"PostToolBatch", "Notification", "SubagentStart", "SubagentStop":
		return map[string]interface{}{"hookSpecificOutput": map[string]interface{}{
			"hookEventName":     event,
			"additionalContext": additional,
		}}
	case "CwdChanged":
		return map[string]interface{}{"watchPaths": []string{}}
	default:
		return map[string]interface{}{"systemMessage": additional}
	}
}

func claudeCodeAdditionalContext(rawAction, severity, reason string, wouldBlock bool) string {
	if rawAction == "allow" || rawAction == "" {
		return ""
	}
	prefix := "DefenseClaw observed"
	if wouldBlock {
		prefix = "DefenseClaw would block this in action mode"
	}
	if reason == "" {
		return fmt.Sprintf("%s a %s Claude Code hook finding.", prefix, severity)
	}
	return fmt.Sprintf("%s a %s Claude Code hook finding: %s", prefix, severity, reason)
}

func reasonOrDefaultClaudeCode(reason string) string {
	if strings.TrimSpace(reason) == "" {
		return "Blocked by DefenseClaw Claude Code policy."
	}
	return reason
}

func claudeCodeToolName(req claudeCodeHookRequest) string {
	if strings.TrimSpace(req.ToolName) != "" {
		return req.ToolName
	}
	return "ClaudeCodeTool"
}

func claudeCodeToolArgs(req claudeCodeHookRequest) json.RawMessage {
	if req.ToolInput == nil {
		return json.RawMessage(`{}`)
	}
	b, err := json.Marshal(req.ToolInput)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}

func claudeCodePromptContent(req claudeCodeHookRequest) string {
	parts := []string{req.Prompt, req.CommandName, req.CommandArgs}
	return strings.Join(nonEmptyStrings(parts...), "\n")
}

func claudeCodeToolOutput(req claudeCodeHookRequest) string {
	parts := []string{claudeCodeString(req.ToolResponse), claudeCodeString(req.ToolCalls), req.Error, req.ErrorDetails}
	return strings.Join(nonEmptyStrings(parts...), "\n")
}

func claudeCodeEventContent(req claudeCodeHookRequest) string {
	fields := []string{
		req.Message,
		req.Title,
		req.FilePath,
		req.Source,
		req.LoadReason,
		req.MemoryType,
		req.MCPServerName,
		req.ElicitationAction,
		req.URL,
		req.OldCWD,
		req.NewCWD,
		req.LastAssistantMessage,
		claudeCodePayloadString(req.Payload, "content"),
		claudeCodePayloadString(req.Payload, "compact_summary"),
		claudeCodePayloadString(req.Payload, "custom_instructions"),
		claudeCodePayloadString(req.Payload, "task_subject"),
		claudeCodePayloadString(req.Payload, "task_description"),
		claudeCodePayloadString(req.Payload, "reason"),
	}
	return strings.Join(nonEmptyStrings(fields...), "\n")
}

func claudeCodeWatchPaths(req claudeCodeHookRequest) []string {
	root := strings.TrimSpace(req.NewCWD)
	if root == "" {
		root = strings.TrimSpace(req.CWD)
	}
	if root == "" {
		return []string{}
	}
	candidates := []string{
		"CLAUDE.md",
		".mcp.json",
		".env",
		".envrc",
		"package.json",
		"pyproject.toml",
		"go.mod",
		"Cargo.toml",
		"requirements.txt",
		filepath.Join(".claude", "settings.json"),
		filepath.Join(".claude", "settings.local.json"),
	}
	out := make([]string, 0, len(candidates))
	for _, p := range candidates {
		if filepath.IsAbs(p) {
			out = append(out, filepath.Clean(p))
			continue
		}
		out = append(out, filepath.Join(root, p))
	}
	return out
}

func nonEmptyStrings(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}

func claudeCodeString(v interface{}) string {
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
		return string(b)
	}
}

func claudeCodePayloadString(payload map[string]interface{}, key string) string {
	if payload == nil {
		return ""
	}
	return claudeCodeString(payload[key])
}

func (a *APIServer) scanClaudeCodeEventFile(ctx context.Context, req claudeCodeHookRequest) *ToolInspectVerdict {
	target := strings.TrimSpace(req.FilePath)
	if target == "" {
		return nil
	}
	if !filepath.IsAbs(target) && req.CWD != "" {
		target = filepath.Join(req.CWD, target)
	}
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		return nil
	}
	target = resolved
	info, err := os.Stat(target)
	if err != nil || info.IsDir() {
		return nil
	}

	rulesDir := ""
	if a.scannerCfg != nil {
		rulesDir = a.scannerCfg.Scanners.CodeGuard
	}
	cg := scanner.NewCodeGuardScanner(rulesDir)
	result, err := cg.Scan(ctx, target)
	if err != nil {
		return nil
	}
	if a.logger != nil {
		_ = a.logger.LogScanWithCorrelation(ctx, result, "", ScanCorrelationFromContext(ctx))
	}
	if len(result.Findings) == 0 || result.MaxSeverity() == scanner.SeverityInfo {
		return &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	}
	findings := make([]string, 0, len(result.Findings))
	for _, f := range result.Findings {
		findings = append(findings, f.ID)
		if len(findings) >= 20 {
			break
		}
	}
	maxSeverity := result.MaxSeverity()
	action := "alert"
	if maxSeverity == scanner.SeverityCritical || maxSeverity == scanner.SeverityHigh {
		action = "block"
	}
	return &ToolInspectVerdict{
		Action:   action,
		Severity: string(maxSeverity),
		Reason:   fmt.Sprintf("CodeGuard found %d finding(s) in Claude Code %s file", len(findings), req.HookEventName),
		Findings: findings,
	}
}

func (a *APIServer) scanClaudeCodeChangedFiles(ctx context.Context, req claudeCodeHookRequest) *ToolInspectVerdict {
	targets := a.claudeCodeStopTargets(ctx, req)
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
			findings = append(findings, f.ID)
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
		Reason:   fmt.Sprintf("CodeGuard found %d finding(s) in Claude Code changed files", len(findings)),
		Findings: findings,
	}
}

func (a *APIServer) claudeCodeStopTargets(ctx context.Context, req claudeCodeHookRequest) []string {
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
		for _, p := range a.scannerCfg.ConnectorHookConfig("claudecode").ScanPaths {
			add(p)
		}
	}
	changedFiles, gitErr := gitChangedFiles(ctx, req.CWD)
	if gitErr != nil {
		fmt.Fprintf(os.Stderr, "[claude-code-hook] WARNING: git scan failed: %v — scanning configured paths only\n", gitErr)
	}
	for _, p := range changedFiles {
		add(p)
	}
	if len(out) > 200 {
		return out[:200]
	}
	return out
}

func (a *APIServer) scanClaudeCodeComponents(ctx context.Context, req claudeCodeHookRequest) int {
	if a.scannerCfg == nil {
		return 0
	}
	if !req.ScanComponents && !a.claudeCodeComponentScanDue() {
		return 0
	}
	targets := claudeCodeComponentTargets(req.CWD)
	count := 0
	for component, paths := range targets {
		for _, p := range paths {
			if _, err := os.Stat(p); err != nil {
				continue
			}
			if a.scanClaudeCodeComponent(ctx, component, p) {
				count++
			}
		}
	}
	return count
}

func (a *APIServer) claudeCodeComponentScanDue() bool {
	interval := 60 * time.Minute
	if a.scannerCfg != nil && a.scannerCfg.ConnectorHookConfig("claudecode").ComponentScanIntervalMinutes > 0 {
		interval = time.Duration(a.scannerCfg.ConnectorHookConfig("claudecode").ComponentScanIntervalMinutes) * time.Minute
	}
	a.claudeCodeMu.Lock()
	defer a.claudeCodeMu.Unlock()
	if !a.claudeCodeLastComponentScan.IsZero() && time.Since(a.claudeCodeLastComponentScan) < interval {
		return false
	}
	a.claudeCodeLastComponentScan = time.Now()
	return true
}

// claudeCodeComponentTargets returns expanded, deduplicated targets for
// runtime scanning. This is the detailed counterpart of
// ClaudeCodeConnector.ComponentTargets() (which returns structural parent
// directories for the fsnotify watcher and CLI). Changes to the directory
// layout should be reflected in both places.
func claudeCodeComponentTargets(cwd string) map[string][]string {
	targets := map[string][]string{
		"skill":   {},
		"plugin":  {},
		"mcp":     {},
		"agent":   {},
		"command": {},
		"config":  {},
	}
	home, err := os.UserHomeDir()
	if err == nil {
		claudeHome := filepath.Join(home, ".claude")
		targets["skill"] = append(targets["skill"], childDirs(filepath.Join(claudeHome, "skills"))...)
		targets["plugin"] = append(targets["plugin"], childDirs(filepath.Join(claudeHome, "plugins"))...)
		targets["agent"] = append(targets["agent"], childDirs(filepath.Join(claudeHome, "agents"))...)
		targets["command"] = append(targets["command"], childDirs(filepath.Join(claudeHome, "commands"))...)
		targets["mcp"] = append(targets["mcp"], existingFiles(filepath.Join(claudeHome, "settings.json"))...)
		targets["config"] = append(targets["config"], existingFiles(filepath.Join(claudeHome, "settings.json"), filepath.Join(claudeHome, "rules"), filepath.Join(home, ".claude.json"))...)
		targets["config"] = append(targets["config"], childDirs(filepath.Join(claudeHome, "rules"))...)
	}
	for _, root := range workspaceCodexRoots(cwd) {
		claudeDir := filepath.Join(root, ".claude")
		targets["skill"] = append(targets["skill"], childDirs(filepath.Join(claudeDir, "skills"))...)
		targets["plugin"] = append(targets["plugin"], childDirs(filepath.Join(claudeDir, "plugins"))...)
		targets["agent"] = append(targets["agent"], childDirs(filepath.Join(claudeDir, "agents"))...)
		targets["command"] = append(targets["command"], childDirs(filepath.Join(claudeDir, "commands"))...)
		targets["mcp"] = append(targets["mcp"], existingFiles(filepath.Join(root, ".mcp.json"), filepath.Join(claudeDir, "settings.json"), filepath.Join(claudeDir, "settings.local.json"))...)
		targets["config"] = append(targets["config"], existingFiles(
			filepath.Join(root, "CLAUDE.md"),
			filepath.Join(claudeDir, "settings.json"),
			filepath.Join(claudeDir, "settings.local.json"),
			filepath.Join(claudeDir, "rules"),
		)...)
		targets["config"] = append(targets["config"], childDirs(filepath.Join(claudeDir, "rules"))...)
	}
	for k, paths := range targets {
		targets[k] = uniqueExistingPaths(paths)
	}
	return targets
}

func (a *APIServer) scanClaudeCodeComponent(ctx context.Context, component, target string) bool {
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
	default:
		rulesDir := ""
		if a.scannerCfg != nil {
			rulesDir = a.scannerCfg.Scanners.CodeGuard
		}
		cg := scanner.NewCodeGuardScanner(rulesDir)
		result, err = cg.Scan(scanCtx, target)
	}
	if err != nil {
		return false
	}
	if result != nil && a.logger != nil {
		_ = a.logger.LogScanWithCorrelation(ctx, result, "", ScanCorrelationFromContext(ctx))
	}
	return true
}
