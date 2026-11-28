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
	"runtime"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// sandboxShellCommand returns the command of a hook request's shell tool
// call in the plain shell shape, and the tool to judge it as: actionTool,
// the tool the call's arguments are judged as, or "shell" for Cursor's
// beforeShellExecution, whose payload is the call. It returns nil for any
// call that is not a shell tool call with a command, and for a Codex shell
// call on a host where Codex runs it in PowerShell: there the Codex hook
// judges the command alone as PowerShell (codexPowerShellCommand).
//
// Host traffic is judged this way too (GAP-0686): an argument key the
// connector's projection does not know left the parse partial, so the
// command reached no rule and a call the same command alone blocks was
// allowed. Harnesses such as OpenCode ignore such keys and run the command.
func sandboxShellCommand(ctx context.Context, connectorName, event, toolName, actionTool string, args json.RawMessage) (json.RawMessage, string) {
	if codexShellRunsPowerShell && !sandboxHookForConnector(ctx, connectorName) &&
		strings.EqualFold(strings.TrimSpace(connectorName), "codex") {
		return nil, ""
	}
	if strings.EqualFold(strings.TrimSpace(connectorName), "cursor") {
		if command, ok := connector.CursorShellCommandArgs(event, args); ok {
			return command, "shell"
		}
	}
	if command, ok := connector.ShellCommandArgs(connectorName, toolName, args); ok {
		return command, shellCommandJudgeTool(connectorName, toolName, actionTool)
	}
	return nil, ""
}

// shellCommandJudgeTool is the tool a shell call's command alone is judged
// as: the PowerShell tool for Copilot's powershell tool, whose commands
// Copilot runs in PowerShell, else actionTool. On Windows the call itself is
// judged as shell (agentHookTrustedActionTool), in the dialect its text
// infers, and a launcher line inferred as POSIX loses the backslashes of an
// unquoted Windows path: pwsh -wd C:\Users\a\.defenseclaw -Command
// "Set-Content config.yaml ..." moved to a folder that does not exist, so the
// write was allowed while the same move spelled Set-Location blocked
// (rel-1-0-10:GAP-0198). As for Codex (codexPowerShellCommand), the command
// alone is also judged as PowerShell, the launcher reading of the PowerShell
// tool; that reading only adds to the call's verdict.
func shellCommandJudgeTool(connectorName, toolName, actionTool string) string {
	if strings.EqualFold(strings.TrimSpace(connectorName), "copilot") &&
		strings.EqualFold(strings.TrimSpace(toolName), "powershell") {
		return "powershell"
	}
	return actionTool
}

// kiroPwshRunsPowerShell is set where kiro-cli runs its execute_pwsh tool's
// command in PowerShell: a Windows host (kiro-cli --v3, 2.35.1). A variable,
// as codexShellRunsPowerShell is, so a test can judge the Windows route.
var kiroPwshRunsPowerShell = runtime.GOOS == "windows"

// kiroPowerShellCommand reports a Kiro execute_pwsh call on a host where Kiro
// runs its command in PowerShell. Its command alone is also judged as the
// PowerShell tool, next to the shell reading every shell call has
// (rel-1-0-10:GAP-1557). That reading is added, never put in place of the
// shell one: judged as PowerShell alone, a second command key spelled
// Command next to rm -rf, and the conflict of two command keys, were lost and
// the call was allowed (GAP-1940).
func kiroPowerShellCommand(ctx context.Context, connectorName string, req *ToolInspectRequest, commandTool string) bool {
	return kiroPwshRunsPowerShell && req != nil && commandTool != "powershell" &&
		strings.EqualFold(strings.TrimSpace(connectorName), "kiro") &&
		strings.EqualFold(strings.TrimSpace(req.Tool), "execute_pwsh") &&
		!sandboxHookForConnector(ctx, connectorName)
}

// inspectSandboxShellToolPolicyCtx is inspectTrustedToolPolicyCtx for a
// hook tool call, which for a shell tool call also judges the command on
// its own. command is the call's command in the plain shell shape and
// commandTool the tool to judge it as (sandboxShellCommand, or
// codexPowerShellCommand for a Codex shell call on Windows); with no command
// it is inspectTrustedToolPolicyCtx, except for a connector's shell tool
// (connector.IsShellTool) whose parse is not complete: with no single
// command argument to judge, that call cannot be verified and takes a
// conservative CRITICAL finding (unverifiedShellCommandFinding).
//
// A shell call's arguments reach the trusted-action parser through the
// connector's projection, which takes out only the arguments it knows with
// the values it expects. Any other argument, or a known one of another type,
// leaves the parse partial, so no command rule can prove its match and a
// CRITICAL command finding stays an allowed candidate. A sandbox's hooks are
// the only gate on its tool calls, and its harness usually runs with its own
// permission prompts off, so there one unlisted argument turned a block into
// an allow; on a host, a harness that ignores the unknown argument runs the
// command just the same. When the call's parse is not complete, the command is judged
// again in the plain shape, in the call's working directory, and the verdict
// takes the stronger of the two. The plain shape only ever adds to the
// verdict: the arguments it drops may change how the command runs, so it
// never lifts a block, and a call the static allow list, managed mode or a
// complete parse settles is left as it is.
func (a *APIServer) inspectSandboxShellToolPolicyCtx(
	ctx context.Context,
	req *ToolInspectRequest,
	action trustedActionRequest,
	command json.RawMessage,
	commandTool string,
) (result *ToolInspectVerdict) {
	ctx = withCallTargetMemo(ctx)
	connectorName := action.Connector
	if req != nil {
		connectorName = firstNonEmpty(req.Connector, action.Connector)
	}
	unverified := len(command) == 0 && req != nil && connector.IsShellTool(connectorName, req.Tool) &&
		!connector.BlankShellCommand(connectorName, req.Tool, req.Args)
	if len(command) == 0 && !unverified {
		return a.inspectTrustedToolPolicyCtx(ctx, req, action)
	}
	var primary actionfacts.Facts
	dispatched := false
	record := action.record
	action.record = func(facts actionfacts.Facts, findings []RuleFinding) {
		primary, dispatched = facts, true
		if record != nil {
			record(facts, findings)
		}
	}
	// The second command reading can still block a call the first reading
	// allowed. Hold cross-call aliases until that final merged verdict.
	if deferEffectAlias(action) {
		if action.aliasPending == nil {
			aliasPending := &effectAliasPending{}
			action.aliasPending = aliasPending
			defer func() {
				if aliasVerdictCanRun(result) {
					aliasPending.commit()
				}
			}()
		}
	}
	verdict := a.inspectTrustedToolPolicyCtx(ctx, req, action)
	if verdict == nil || !dispatched || primary.Authoritative() {
		return verdict
	}
	if unverified {
		// Any parse that is not complete: partial or ambiguous with extra
		// keys, and invalid or not applicable when the command key is
		// missing or holds no command string (a number, null, blank text,
		// an object).
		return mergeSandboxShellCommandVerdict(ctx, a.decisionConfig(ctx), connectorName, verdict,
			[]RuleFinding{unverifiedShellCommandFinding(action.EnforcementCapable)})
	}
	powerShell := kiroPowerShellCommand(ctx, connectorName, req, commandTool)
	sameReading := commandTool == action.Input.Tool && bytes.Equal(command, action.Input.Args)
	if sameReading && !powerShell {
		return verdict
	}
	if action.EnforcementCapable && trustedCallOverStatementBudget(action.Input, primary) {
		// The call is already refused over the statement budget, and this
		// reading only adds to its verdict: a second, PowerShell reading
		// of a 3000-statement Codex call cost a Windows gateway about a
		// second (rel-1-0-2:GAP-0568).
		return verdict
	}
	commandAlone := func(tool string) []RuleFinding {
		input := action.Input
		input.Tool, input.Args = tool, command
		if action.windowsShellDialect {
			// The full call's hint was inferred from arguments whose parse is
			// not complete, so it may be empty; the command alone is judged in
			// the dialect inferred from it, as the same call without the extra
			// keys is (GAP-0686).
			input.DialectHint = agentHookWindowsShellDialect(input)
		}
		return dispatchTrustedAction(ctx, trustedActionRequest{
			Input:                         input,
			LegacyText:                    string(command),
			Connector:                     action.Connector,
			EnforcementCapable:            action.EnforcementCapable,
			ManagedHookOverflowHold:       action.ManagedHookOverflowHold,
			DowngradeReadOnlyDataArgs:     action.DowngradeReadOnlyDataArgs,
			SkipLocalFilesystemResolution: action.SkipLocalFilesystemResolution,
			ResolvedWriteTargets:          action.ResolvedWriteTargets,
			ShellStartup:                  action.ShellStartup,
			SandboxGuestCWD:               action.SandboxGuestCWD,
			guestToolCWDUnresolved:        action.guestToolCWDUnresolved,
			windowsDialectReadings:        action.windowsDialectReadings,
		})
	}
	var findings []RuleFinding
	if !sameReading {
		findings = commandAlone(commandTool)
	}
	if powerShell {
		// Kiro runs execute_pwsh in PowerShell here: the PowerShell reading
		// of the command only adds findings (kiroPowerShellCommand).
		findings = mergeBoundedFindings(findings, commandAlone("powershell"))
	}
	if plain, ok := codexPlainShellCommand(a.decisionConfig(ctx), connectorName, req, action, commandTool); ok {
		// Codex runs the command in PowerShell here, but the text may be
		// one that PowerShell reads no path of (touch ~/.netrc): judged as
		// PowerShell alone, a credential write in an exec_command call,
		// whose arguments leave the parse partial, only alerted, while the
		// same text in the Bash shape was blocked (GAP-1076). The command
		// alone is also judged as the call tool, in the dialect the text
		// infers, as the Bash shape is; this reading only adds findings.
		input := action.Input
		input.Args = plain
		input.DialectHint = ""
		if runtime.GOOS == "windows" {
			input.DialectHint = agentHookWindowsShellDialect(input)
		}
		// A call already in the plain shape, in the same dialect, was
		// judged so by its first reading: judging it again repeated every
		// reader of that text, on Windows the script and folder-link walks
		// too, and a writer behind 63 folder links answered at the Codex
		// hook deadline (GAP-1079).
		if !bytes.Equal(plain, action.Input.Args) || input.DialectHint != action.Input.DialectHint {
			findings = mergeBoundedFindings(findings, dispatchTrustedAction(ctx, trustedActionRequest{
				Input:                         input,
				LegacyText:                    string(plain),
				Connector:                     action.Connector,
				EnforcementCapable:            action.EnforcementCapable,
				ManagedHookOverflowHold:       action.ManagedHookOverflowHold,
				DowngradeReadOnlyDataArgs:     action.DowngradeReadOnlyDataArgs,
				SkipLocalFilesystemResolution: action.SkipLocalFilesystemResolution,
				ResolvedWriteTargets:          action.ResolvedWriteTargets,
				SandboxGuestCWD:               action.SandboxGuestCWD,
				guestToolCWDUnresolved:        action.guestToolCWDUnresolved,
				windowsDialectReadings:        action.windowsDialectReadings,
			}))
		}
	}
	return withSecondReadingDetections(
		mergeSandboxShellCommandVerdict(ctx, a.decisionConfig(ctx), connectorName, verdict, findings),
		findings,
	)
}

// withSecondReadingDetections records on verdict the detection-only findings
// of loaded rule-pack rules that the second reading proved, as the first
// reading records its own: listed with their severity, the action unchanged.
// On a Windows host Codex runs its Bash tool in PowerShell, and the call's own
// reading of PowerShell text it infers as POSIX can fail, so the PowerShell
// reading here is the only one that reads the call. The merge keeps only the
// findings that decide, so a detection-only rule proved by that reading (the
// PowerShell TCP command loop) never reached the verdict or the audit, while
// the same text on a PowerShell tool reported it (rel-1-0-10:GAP-0161).
// Findings of no rule-pack rule (parse and limit records of the second
// reading) are not added: the call's own reading reports its own.
func withSecondReadingDetections(verdict *ToolInspectVerdict, findings []RuleFinding) *ToolInspectVerdict {
	if verdict == nil {
		return nil
	}
	var detections []RuleFinding
	for _, finding := range findings {
		if finding.contributesToEnforcement() || finding.contributesToAlertOnly() ||
			!activeRulePackRuleID(finding.RuleID) {
			continue
		}
		detections = append(detections, finding)
	}
	if len(detections) == 0 {
		return verdict
	}
	out := withSandboxShellCommandFindings(verdict, detections)
	if severity := HighestSeverity(detections); severityRank[severity] > severityRank[strings.ToUpper(strings.TrimSpace(out.Severity))] {
		raised := *out
		raised.Severity = severity
		raised.Confidence = HighestConfidence(detections, severity)
		out = &raised
	}
	return out
}

// codexPlainShellCommand is the command of a Codex shell call in the plain
// shell shape, to judge as the call tool next to its PowerShell reading
// (codexPowerShellCommand): for a call whose tool names no PowerShell, on a
// host outside Secure Client.
func codexPlainShellCommand(cfg *config.Config, connectorName string, req *ToolInspectRequest, action trustedActionRequest, commandTool string) (json.RawMessage, bool) {
	if req == nil || commandTool != "powershell" || !strings.EqualFold(strings.TrimSpace(connectorName), "codex") ||
		trustedPowerShellExecutionTool(action.Input.Tool) || cfg != nil && cfg.SecureClientIntegration() {
		return nil, false
	}
	return connector.ShellCommandArgs("codex", req.Tool, action.Input.Args)
}

const (
	// unverifiedShellCommandRuleID is the conservative finding of a shell
	// tool call whose parse is not complete and that has no single command
	// argument to judge on its own.
	unverifiedShellCommandRuleID = "TOOL-ARGS-UNVERIFIED"
	unverifiedShellCommandTitle  = "Shell tool call without one command argument that can be verified"
)

// unverifiedShellCommandFinding is the conservative CRITICAL finding of a
// shell tool call that cannot be verified (GAP-0686). Like every finding, it
// only blocks where the call is enforcement-capable (observe mode records
// would_block).
func unverifiedShellCommandFinding(enforcementCapable bool) RuleFinding {
	enforcement := enforcingProof
	if !enforcementCapable {
		enforcement = recordProof
	}
	return RuleFinding{
		RuleID:     unverifiedShellCommandRuleID,
		Title:      unverifiedShellCommandTitle,
		Severity:   "CRITICAL",
		Confidence: 1,
		Tags:       []string{"tool-arguments"},
		LineNumber: 1,
		Proof:      enforcement,
	}
}

// mergeSandboxShellCommandVerdict raises verdict to the action findings, the
// command judged on its own, decide at the connector's thresholds, when that
// is stronger. The deciding findings replace the call's findings of the same
// rules (there only candidates) and name the reason.
//
// A verdict at least as strong keeps its action, severity and reason, but
// still records the deciding findings it does not name yet: both readings of
// the call are judged, the verdict is the stricter one, and neither is
// silently dropped. A rule the full call proves from a partial parse
// (withProvenScopeFindings) already blocks it, and the conservative finding
// of the second reading (TOOL-ARGS-CONFLICT for two spellings of the command
// key, TOOL-ARGS-UNVERIFIED for no single command) was lost from the verdict
// and its audit (rel-1-0-10:GAP-0833). A verdict that gains nothing is
// returned unchanged.
func mergeSandboxShellCommandVerdict(ctx context.Context, cfg *config.Config, connectorName string, verdict *ToolInspectVerdict, findings []RuleFinding) *ToolInspectVerdict {
	action, floorConfirm := profileMeetDecisionForFindings(ctx, cfg, connectorName, findings, true, false)
	deciding := make([]RuleFinding, 0, len(findings))
	for _, finding := range findings {
		if finding.contributesToEnforcement() || finding.contributesToAlertOnly() {
			deciding = append(deciding, finding)
		}
	}
	if strongerGuardrailAction(verdict.Action, action) == verdict.Action {
		out := verdict
		if verdict.decisionConfirm && action == guardrailActionConfirm && !floorConfirm {
			// A rule confirms the call too: the confirm is no longer the
			// decision model's alone, so it keeps the rule mapping (a block
			// where the agent cannot ask).
			copied := *verdict
			copied.decisionConfirm = false
			out = &copied
		}
		return withSandboxShellCommandFindings(out, deciding)
	}
	merged := *verdict
	merged.Action = action
	// The action is the rules' now (stronger than the verdict's): a
	// confirm floor's confirm keeps its no-ask alert.
	merged.decisionConfirm = floorConfirm
	merged.DetailedFindings = append([]RuleFinding(nil), verdict.DetailedFindings...)
	merged.Findings = append([]string(nil), verdict.Findings...)
	reasons := make([]string, 0, minInt(len(deciding), 5))
	for _, finding := range deciding {
		label := finding.RuleID + ":" + finding.Title
		if len(reasons) < 5 {
			reasons = append(reasons, label)
		}
		replaced := false
		for i := range merged.DetailedFindings {
			if merged.DetailedFindings[i].RuleID == finding.RuleID {
				merged.DetailedFindings[i], replaced = finding, true
			}
		}
		if !replaced {
			merged.DetailedFindings = append(merged.DetailedFindings, finding)
		}
		if !slices.Contains(merged.Findings, label) {
			merged.Findings = append(merged.Findings, label)
		}
	}
	if severity := HighestSeverity(deciding); severityRank[severity] > severityRank[strings.ToUpper(strings.TrimSpace(merged.Severity))] {
		merged.Severity = severity
		merged.Confidence = HighestConfidence(deciding, severity)
	}
	merged.Reason = "matched: " + strings.Join(reasons, ", ")
	return &merged
}

// withSandboxShellCommandFindings records on verdict the deciding findings of
// a second reading whose action is not stronger: each rule verdict does not
// name yet is added to its findings, and its action, severity and reason are
// kept. With nothing to add, verdict itself is returned.
func withSandboxShellCommandFindings(verdict *ToolInspectVerdict, deciding []RuleFinding) *ToolInspectVerdict {
	var added []RuleFinding
	for _, finding := range deciding {
		label := finding.RuleID + ":" + finding.Title
		if slices.Contains(verdict.Findings, label) ||
			slices.ContainsFunc(added, func(f RuleFinding) bool { return f.RuleID == finding.RuleID }) {
			continue
		}
		added = append(added, finding)
	}
	if len(added) == 0 {
		return verdict
	}
	out := *verdict
	out.Findings = append([]string(nil), verdict.Findings...)
	out.DetailedFindings = append([]RuleFinding(nil), verdict.DetailedFindings...)
	for _, finding := range added {
		out.Findings = append(out.Findings, finding.RuleID+":"+finding.Title)
		if !slices.ContainsFunc(out.DetailedFindings, func(f RuleFinding) bool { return f.RuleID == finding.RuleID }) {
			out.DetailedFindings = append(out.DetailedFindings, finding)
		}
	}
	return &out
}
