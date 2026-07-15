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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

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
	RedactionEnabled *bool `json:"-"`
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
// dispatch metric, dedup, trace propagation, OTel emissions) in
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
			Tool:      "message",
			Content:   req.Prompt,
			Direction: "prompt",
			Connector: "codex",
		})
	case "PreToolUse", "PermissionRequest":
		verdict = a.inspectToolPolicy(&ToolInspectRequest{
			Tool:          codexToolName(req),
			Args:          codexToolArgs(req),
			Direction:     "tool_call",
			Connector:     "codex",
			MCPServerName: firstNonEmpty(req.MCPServerName, payloadString(req.Payload, "mcp_server_name")),
		})
		if decision, matched := a.codexMCPAssetDecision(ctx, req); matched {
			assetDecisions = append(assetDecisions, runtimeAssetDecision{targetType: "mcp", decision: decision})
		}
		if decision, matched := a.codexSkillAssetDecision(ctx, req); matched {
			assetDecisions = append(assetDecisions, runtimeAssetDecision{targetType: "skill", decision: decision})
		}
	case "PostToolUse":
		verdict = a.inspectMessageContent(ctx, &ToolInspectRequest{
			Tool:      "message",
			Content:   codexToolResponseString(req.ToolResponse),
			Direction: "tool_result",
			Connector: "codex",
		})
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
	// Emit per-rule findings FIRST so the notification + audit
	// rows produced below can carry the resulting evaluation_id
	// and top rule_ids — keeping the SIEM pivot key identical
	// across audit log, gateway.jsonl, OS notification, and the
	// HTTP response body.
	evalCtx := a.emitHookRuleFindings(ctx, "codex", req.HookEventName, verdict,
		hookTargetTypeForEvent(req.HookEventName), time.Since(t0))
	if !hookNotificationCoveredByAssetPolicy(rawActionBeforeAssets, assetDecisions) {
		a.dispatchCodexHookNotification(req, action, rawAction, verdict.Severity, verdict.Reason, wouldBlock, evalCtx,
			sinkPolicyFor(ctx, verdict.RedactionEnabled))
	}
	resp := codexResponseFor(req.HookEventName, action, rawAction, verdict.Severity, verdict.Reason, verdict.Findings, mode, wouldBlock)
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
	// one; otherwise default to the historical ForSinkReason behavior.
	safeReason := redaction.ReasonForSink(reason, notificationSinkPolicy(policy))
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
	if a.scannerCfg == nil {
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
	if a.scannerCfg.ManualConnectorConfigured("codex") && !a.scannerCfg.Guardrail.EffectiveEnabled("codex") {
		return false
	}
	if a.scannerCfg.ConnectorHookConfig("codex").Enabled {
		return true
	}
	if a.health != nil && a.health.HasConnectorSource("codex", "automatic") && a.scannerCfg.ApplicationProtection.EffectiveEnabled("codex") {
		return true
	}
	// Multi-connector: membership in guardrail.connectors opts codex in
	// even when it is not the singular primary (no-op for single).
	if a.scannerCfg.Guardrail.HasConnector("codex") {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(a.scannerCfg.Guardrail.Connector), "codex")
}

func (a *APIServer) codexMode() string {
	mode := "observe"
	if a.scannerCfg != nil {
		mode = strings.TrimSpace(a.scannerCfg.ConnectorHookConfig("codex").Mode)
		if mode == "" || mode == "inherit" {
			// Per-connector guardrail override wins over global mode.
			mode = strings.TrimSpace(a.scannerCfg.EffectiveGuardrailModeForConnector("codex"))
		}
	}
	return normalizeAgentHookMode(mode)
}

func codexResponseFor(event, action, rawAction, severity, reason string, findings []string, mode string, wouldBlock bool) codexHookResponse {
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
	additional := codexAdditionalContext(rawAction, severity, safeReason, wouldBlock)
	resp := codexHookResponse{
		Action:            action,
		RawAction:         rawAction,
		Severity:          severity,
		Reason:            safeReason,
		Findings:          findings,
		Mode:              mode,
		WouldBlock:        wouldBlock,
		AdditionalContext: additional,
	}
	resp.CodexOutput = codexOutput(event, action, rawAction, safeReason, additional)
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

func codexAdditionalContext(rawAction, severity, reason string, wouldBlock bool) string {
	if rawAction == "allow" || rawAction == "" {
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
