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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	gatewayconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// Claude Cowork reaches the claudecode route: Claude Desktop runs it with the
// Claude Code engine it bundles, and that engine runs the Claude Code hooks
// (managed settings, plugins) on the device. Two things differ from a
// terminal session:
//   - the hook names the call's Cowork session (hookexec.CoworkHeader), which
//     the audit records as surface "cowork" with the session, the prompt and
//     the connected folders (a path-class field);
//   - Cowork's own tools are MCP tools of servers the engine hosts in process
//     (connector.CoworkToolClassFor). Its VM shell and its web fetch are
//     inspected exactly as Claude Code's Bash and WebFetch, and a browser
//     navigation's URL as a WebFetch URL; every other Cowork tool keeps the
//     generic MCP tool path.

// Audit extra keys of a Cowork call.
const (
	coworkSurfaceExtra   = "surface"
	coworkSessionExtra   = "cowork_session_id"
	coworkPromptExtra    = "prompt_id"
	coworkToolClassExtra = "cowork_tool_class"
)

type coworkContextKey struct{}

// withCowork keeps the Cowork context a claudecode hook sent. Any local
// process can send the header, so it is attribution for the audit and the
// health counters only, never a policy input or an identity.
func withCowork(ctx context.Context, header http.Header, connectorName string) context.Context {
	if canonicalConnectorRulePackKey(connectorName) != "claudecode" {
		return ctx
	}
	value := header.Get(hookexec.CoworkHeader)
	if value == "" {
		return ctx
	}
	cowork, ok := hookexec.ParseCoworkHeader(value)
	if !ok {
		return ctx
	}
	return context.WithValue(ctx, coworkContextKey{}, cowork)
}

// coworkFromContext is the request's Cowork context, if it has one.
func coworkFromContext(ctx context.Context) (hookexec.CoworkContext, bool) {
	if ctx == nil {
		return hookexec.CoworkContext{}, false
	}
	cowork, ok := ctx.Value(coworkContextKey{}).(hookexec.CoworkContext)
	return cowork, ok
}

// coworkSurfaceAuditExtra names the surface and the session of a Cowork
// call for its audit row; nil outside Cowork.
func coworkSurfaceAuditExtra(ctx context.Context) map[string]string {
	cowork, ok := coworkFromContext(ctx)
	if !ok {
		return nil
	}
	extra := map[string]string{coworkSurfaceExtra: gatewayconnector.CoworkSurface}
	if cowork.SessionID != "" {
		extra[coworkSessionExtra] = cowork.SessionID
	}
	return extra
}

// coworkCallAuditExtra adds the prompt and the Cowork tool class of a Cowork
// call. The class is recorded for every Cowork tool, so a scheduled-task
// creation or a granted delete is visible in the audit whatever the verdict.
func coworkCallAuditExtra(ctx context.Context, payload map[string]interface{}, toolName string) map[string]string {
	if _, ok := coworkFromContext(ctx); !ok {
		return nil
	}
	extra := map[string]string{}
	if id := coworkIdentifier(payloadString(payload, "prompt_id")); id != "" {
		extra[coworkPromptExtra] = id
	}
	if class, ok := gatewayconnector.CoworkToolClassFor(strings.TrimSpace(toolName)); ok {
		extra[coworkToolClassExtra] = string(class)
	}
	return extra
}

// coworkSurfaceV8 is the defenseclaw.agent.surface attribute of a hook
// decision record: cowork for a Cowork call, absent otherwise.
func coworkSurfaceV8(ctx context.Context) observability.Optional[string] {
	if _, ok := coworkFromContext(ctx); ok {
		return observability.Present(gatewayconnector.CoworkSurface)
	}
	return observability.Absent[string]()
}

// coworkWorkspaceHostPaths are the connected folders of a Cowork call.
func coworkWorkspaceHostPaths(ctx context.Context) []string {
	cowork, _ := coworkFromContext(ctx)
	return cowork.WorkspaceHostPaths
}

// coworkIdentifier keeps a UUID-like identifier ([A-Za-z0-9._:-], at most
// 128 bytes), else "".
func coworkIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return ""
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == ':' {
			continue
		}
		return ""
	}
	return value
}

// claudeCodeCoworkInspection is how a Cowork tool call is inspected.
type claudeCodeCoworkInspection struct {
	// actionTool and args are what the trusted-action parser sees.
	actionTool string
	args       json.RawMessage
	// requestTool replaces the tool name of the inspect request (static
	// tool lists, judge, AID) when the call is proven to come from the
	// engine's own server; "" keeps the native name.
	requestTool string
	// dialect is the shell grammar of the command, or "".
	dialect actionfacts.Dialect
}

// claudeCodeCoworkInspectionFor maps the Cowork tools whose arguments have a
// reviewed native meaning:
//   - mcp__workspace__bash {"command"} runs in the Cowork VM, a Linux guest:
//     it is Claude Code's Bash, read as POSIX on every host;
//   - mcp__workspace__web_fetch {"url"} is Claude Code's WebFetch;
//   - mcp__Claude_Browser__navigate {"url"[, "tabId"]} opens its URL like a
//     WebFetch; another shape keeps the generic MCP path.
//
// The request tool becomes Bash or WebFetch only when the payload's
// mcp_server proves the engine's own workspace server (source "sdk"), so a
// user MCP server that reuses the name keeps its MCP identity and the MCP
// server policy. ok is false for every other tool.
func claudeCodeCoworkInspectionFor(toolName string, args json.RawMessage, payload map[string]interface{}) (claudeCodeCoworkInspection, bool) {
	toolName = strings.TrimSpace(toolName)
	class, known := gatewayconnector.CoworkToolClassFor(toolName)
	if !known {
		return claudeCodeCoworkInspection{}, false
	}
	server, _ := payload["mcp_server"].(map[string]interface{})
	sdk := gatewayconnector.CoworkSDKServer(toolName, server)
	switch class {
	case gatewayconnector.CoworkToolShell:
		out := claudeCodeCoworkInspection{actionTool: "Bash", args: args, dialect: actionfacts.DialectPOSIX}
		if sdk {
			out.requestTool = "Bash"
		}
		return out, true
	case gatewayconnector.CoworkToolFetch:
		out := claudeCodeCoworkInspection{actionTool: "WebFetch", args: args}
		if sdk {
			out.requestTool = "WebFetch"
		}
		return out, true
	case gatewayconnector.CoworkToolBrowserNavigate:
		if url, ok := coworkNavigateURL(args); ok {
			projected, err := json.Marshal(map[string]string{"url": url})
			if err == nil {
				return claudeCodeCoworkInspection{actionTool: "WebFetch", args: projected}, true
			}
		}
	}
	return claudeCodeCoworkInspection{}, false
}

// claudeCodeCoworkInspectionUnder is claudeCodeCoworkInspectionFor under
// cfg: never under Secure Client, which keeps the request of main.
func claudeCodeCoworkInspectionUnder(cfg *config.Config, toolName string, args json.RawMessage, payload map[string]interface{}) (claudeCodeCoworkInspection, bool) {
	if !coworkInspected(cfg) {
		return claudeCodeCoworkInspection{}, false
	}
	return claudeCodeCoworkInspectionFor(toolName, args, payload)
}

// coworkInspected reports whether the Cowork tool mapping applies: every
// profile but Secure Client, which keeps the decisions of main (#1092).
func coworkInspected(cfg *config.Config) bool {
	return cfg == nil || !cfg.SecureClientIntegration()
}

// coworkWorkspaceServerName is the MCP server of Cowork's workspace tools.
const coworkWorkspaceServerName = "workspace"

// claudeCodeCoworkNativeDeny keeps the denies an administrator wrote for a
// Cowork workspace tool under its native name when the call is judged as
// Bash or WebFetch: an MCP server block of "workspace" (defenseclaw mcp
// block, asset_policy.mcp), the account's own MCP block, and a static block
// of mcp__workspace__bash or mcp__workspace__web_fetch. A deny wins; the
// allow list applies to the Bash or WebFetch name the call is judged under.
// nil when nothing denies it (toolBlockListVerdict; the managed AID-only path has no static lists).
// callerCWD is the call's working folder, so a project-scoped MCP admission
// matches as in inspectTrustedToolPolicyCtx.
func (a *APIServer) claudeCodeCoworkNativeDeny(ctx context.Context, nativeTool, callerCWD string) *ToolInspectVerdict {
	return a.toolBlockListVerdict(ctx, &ToolInspectRequest{
		Tool: nativeTool, Connector: "claudecode", MCPServerName: coworkWorkspaceServerName,
		Direction: "tool_call", callerCWD: callerCWD,
	}, nil)
}

// claudeCodeCoworkNativeTool reports a call of the engine's own workspace
// shell or fetch: it is decided as Claude Code's Bash or WebFetch, not as a
// call of an MCP server the user configured (whose admission and server
// policy then do not apply).
func claudeCodeCoworkNativeTool(req claudeCodeHookRequest) bool {
	class, known := gatewayconnector.CoworkToolClassFor(strings.TrimSpace(req.ToolName))
	if !known || (class != gatewayconnector.CoworkToolShell && class != gatewayconnector.CoworkToolFetch) {
		return false
	}
	server, _ := req.Payload["mcp_server"].(map[string]interface{})
	return gatewayconnector.CoworkSDKServer(strings.TrimSpace(req.ToolName), server)
}

// coworkNavigateURL is the URL of a navigate call whose arguments are
// exactly {"url": string} plus an optional numeric "tabId".
func coworkNavigateURL(args json.RawMessage) (string, bool) {
	decoder := json.NewDecoder(bytes.NewReader(args))
	decoder.UseNumber()
	var object map[string]interface{}
	if decoder.Decode(&object) != nil || decoder.More() || len(object) == 0 || len(object) > 2 {
		return "", false
	}
	url, ok := object["url"].(string)
	if !ok || strings.TrimSpace(url) == "" {
		return "", false
	}
	for key, value := range object {
		switch key {
		case "url":
		case "tabId":
			if _, number := value.(json.Number); !number {
				return "", false
			}
		default:
			return "", false
		}
	}
	return url, true
}

// coworkSaveSkillTool and coworkPluginInstallTool are Cowork's skill save
// and plugin suggestion tools. Their input is not documented. The 1.0.8 live
// tests (Claude Desktop 4.16336.0, engine 2.1.317, third-party inference)
// captured save_skill as {"name", "description", "content"};
// suggest_plugin_install was not called (Claude searched with
// mcp__plugins__search_plugins and search_connectors, {"keywords",
// "trigger", "userIntent"}, which name no plugin and keep the generic MCP
// path with class plugin_admission). The asset policy reads the first of
// the listed name keys.
const (
	coworkSaveSkillTool     = "mcp__cowork__save_skill"
	coworkPluginInstallTool = "mcp__plugins__suggest_plugin_install"
)

// claudeCodeCoworkSkillProbe is the skill a save_skill call saves, so an
// asset_policy.skill rule (denied, disabled) refuses saving that skill.
func claudeCodeCoworkSkillProbe(req claudeCodeHookRequest) skillRuntimeProbe {
	if strings.TrimSpace(req.ToolName) != coworkSaveSkillTool {
		return skillRuntimeProbe{}
	}
	raw := firstMapString(req.ToolInput, "skill_name", "skillName", "name", "title")
	name := assetfacts.SkillRuntimeName(raw)
	if name == "" {
		return skillRuntimeProbe{}
	}
	return skillRuntimeProbe{
		TargetType: "skill", SkillName: name, RawName: assetfacts.SkillRawNameIfNormalized(raw, name),
		ToolName: coworkSaveSkillTool, Surface: "hook", Matched: true,
	}
}

// claudeCodeCoworkPluginProbe is the plugin a suggest_plugin_install call
// offers, so an asset_policy.plugin rule refuses offering that plugin.
func claudeCodeCoworkPluginProbe(req claudeCodeHookRequest) skillRuntimeProbe {
	if strings.TrimSpace(req.ToolName) != coworkPluginInstallTool {
		return skillRuntimeProbe{}
	}
	name := strings.TrimSpace(firstMapString(req.ToolInput, "plugin_name", "pluginName", "plugin_id", "pluginId", "plugin", "name"))
	if name == "" || len(name) > 256 {
		return skillRuntimeProbe{}
	}
	return skillRuntimeProbe{
		TargetType: "plugin", SkillName: name, ToolName: coworkPluginInstallTool, Surface: "hook", Matched: true,
	}
}

// maxCoworkPageContentBytes bounds the text of a browser call that is
// checked; a longer text is checked on its first bytes only, like the rule
// scan of any other tool argument.
const maxCoworkPageContentBytes = 64 << 10

// coworkBrowserScriptPath names a browser script for CodeGuard, which picks
// its rules by file type.
const coworkBrowserScriptPath = "cowork-browser-script.js"

// coworkPageContent is the text a browser call puts into a page: the value
// typed by form_input, the script run by javascript_tool. The keys ("value",
// "text") are not live-captured: the third-party Cowork build of the 1.0.8
// live tests (Claude Desktop 4.16336.0) offers no Claude_Browser tools.
func coworkPageContent(req claudeCodeHookRequest) (string, gatewayconnector.CoworkToolClass) {
	class, _ := gatewayconnector.CoworkToolClassFor(strings.TrimSpace(req.ToolName))
	var keys []string
	switch class {
	case gatewayconnector.CoworkToolBrowserForm:
		keys = []string{"value", "text"}
	case gatewayconnector.CoworkToolBrowserScript:
		keys = []string{"text", "code", "script", "javascript"}
	default:
		return "", ""
	}
	for _, key := range keys {
		switch value := req.ToolInput[key].(type) {
		case string:
			if strings.TrimSpace(value) != "" {
				if len(value) > maxCoworkPageContentBytes {
					value = value[:maxCoworkPageContentBytes]
				}
				return value, class
			}
		case json.Number, float64, bool:
			return fmt.Sprint(value), class
		}
	}
	return "", class
}

// inspectClaudeCodeCoworkPageContent checks what a Cowork browser call puts
// into a web page, beside the generic MCP inspection of its arguments:
//   - the typed value and the script against the secret rules, read as
//     outbound data, so a credential typed into or sent from a page gets the
//     verdict a credential in a prompt gets under the profile;
//   - the script with CodeGuard's JavaScript rules, detection only: a page
//     script runs in the browser's sandbox, so CodeGuard's code findings are
//     recorded and alerted, never a block by themselves.
//
// Personal data (an e-mail address, a phone number) is ordinary form input
// and is not checked here. nil when there is nothing to add.
func (a *APIServer) inspectClaudeCodeCoworkPageContent(ctx context.Context, req claudeCodeHookRequest) *ToolInspectVerdict {
	if a.managedAIDOnly() || !coworkInspected(a.decisionConfig(ctx)) {
		return nil
	}
	content, class := coworkPageContent(req)
	if content == "" {
		return nil
	}
	findings := scanContentRuleCategoryWithGeneration(snapshotRulePackGenerationFor(ctx, "claudecode"),
		content, strings.TrimSpace(req.ToolName), ruleContentScopeUntrusted, "secret")
	action := guardrailActionAllow
	if enforceable := enforceableRuleFindings(findings); len(enforceable) > 0 {
		action = profileMeetActionForFindings(ctx, a.decisionConfig(ctx), "claudecode", enforceable, false, true)
	}
	if class == gatewayconnector.CoworkToolBrowserScript {
		rulesDir := ""
		if cfg := a.decisionConfig(ctx); cfg != nil {
			rulesDir = cfg.Scanners.CodeGuard
		}
		scan := scanner.NewCodeGuardScanner(rulesDir).ScanContentWithProvenance(coworkBrowserScriptPath, content)
		codeFindings := codeGuardRuleFindings(codeGuardArgsScan{findings: scan.Findings(), complete: scan.Complete()}, true, false)
		if len(codeFindings) > 0 {
			action = strongerGuardrailAction(action, guardrailActionAlert)
			findings = append(findings, codeFindings...)
		}
	}
	if len(findings) == 0 {
		return nil
	}
	severity := HighestSeverity(findings)
	reasons := make([]string, 0, minInt(len(findings), 5))
	for i, finding := range findings {
		if i >= 5 {
			break
		}
		reasons = append(reasons, finding.RuleID+":"+finding.Title)
	}
	return &ToolInspectVerdict{
		Action: action, Severity: severity, Confidence: HighestConfidence(findings, severity),
		Reason:   "matched: " + strings.Join(reasons, ", "),
		Findings: FindingStrings(findings), DetailedFindings: findings,
	}
}

// mergeToolInspectVerdicts adds another lane's verdict to the call's (the
// Cowork page-content check, a message call's routing values): the stronger
// action and severity win and the findings add up.
func mergeToolInspectVerdicts(base, extra *ToolInspectVerdict) *ToolInspectVerdict {
	if extra == nil {
		return base
	}
	if base == nil {
		return extra
	}
	out := *base
	out.Action = strongerGuardrailAction(base.Action, extra.Action)
	if guardrailSeverityRank(extra.Severity) > guardrailSeverityRank(base.Severity) {
		out.Severity, out.Confidence = extra.Severity, extra.Confidence
	}
	if out.Action != base.Action || strings.TrimSpace(base.Reason) == "" {
		out.Reason = extra.Reason
	}
	// A rule both checks matched is listed once, with the higher-rated of its
	// two findings (the later check's on a tie): the generic scan of a call's
	// arguments rates a rule lower than the page check does, and the routing
	// lane of a message rates it lower than the text lane.
	baseRank, extraRank := map[string]int{}, map[string]int{}
	for _, finding := range base.DetailedFindings {
		baseRank[finding.RuleID] = guardrailSeverityRank(finding.Severity)
	}
	for _, finding := range extra.DetailedFindings {
		extraRank[finding.RuleID] = guardrailSeverityRank(finding.Severity)
	}
	extraWins := func(id string) bool {
		er, inExtra := extraRank[id]
		br, inBase := baseRank[id]
		return inExtra && (!inBase || er >= br)
	}
	baseWins := func(id string) bool {
		_, inBase := baseRank[id]
		return inBase && !extraWins(id)
	}
	out.Findings, out.DetailedFindings = nil, nil
	for _, finding := range base.Findings {
		if id, _, _ := strings.Cut(finding, ":"); !extraWins(id) {
			out.Findings = append(out.Findings, finding)
		}
	}
	for _, finding := range base.DetailedFindings {
		if !extraWins(finding.RuleID) {
			out.DetailedFindings = append(out.DetailedFindings, finding)
		}
	}
	for _, finding := range extra.Findings {
		if id, _, _ := strings.Cut(finding, ":"); !baseWins(id) {
			out.Findings = append(out.Findings, finding)
		}
	}
	for _, finding := range extra.DetailedFindings {
		if !baseWins(finding.RuleID) {
			out.DetailedFindings = append(out.DetailedFindings, finding)
		}
	}
	return &out
}
