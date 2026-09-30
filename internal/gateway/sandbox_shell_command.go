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
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// sandboxShellCommand returns the command of a sandbox request's shell tool
// call in the plain shell shape, and the tool to judge it as: actionTool,
// the tool the call's arguments are judged as, or "shell" for Cursor's
// beforeShellExecution, whose payload is the call. It returns nil for host
// traffic and for any call that is not a shell tool call with a command.
func sandboxShellCommand(ctx context.Context, connectorName, event, toolName, actionTool string, args json.RawMessage) (json.RawMessage, string) {
	if !sandboxHookForConnector(ctx, connectorName) {
		return nil, ""
	}
	if strings.EqualFold(strings.TrimSpace(connectorName), "cursor") {
		if command, ok := connector.CursorShellCommandArgs(event, args); ok {
			return command, "shell"
		}
	}
	if command, ok := connector.ShellCommandArgs(connectorName, toolName, args); ok {
		return command, actionTool
	}
	return nil, ""
}

// inspectSandboxShellToolPolicyCtx is inspectTrustedToolPolicyCtx for a
// hook tool call, which for a sandbox shell tool call also judges the
// command on its own. command is the call's command in the plain shell
// shape and commandTool the tool to judge it as (sandboxShellCommand); with
// no command it is inspectTrustedToolPolicyCtx.
//
// A shell call's arguments reach the trusted-action parser through the
// connector's projection, which takes out only the arguments it knows with
// the values it expects. Any other argument, or a known one of another type,
// leaves the parse partial, so no command rule can prove its match and a
// CRITICAL command finding stays an allowed candidate. A sandbox's hooks are
// the only gate on its tool calls, and its harness usually runs with its own
// permission prompts off, so there one unlisted argument turned a block into
// an allow. When the call's parse is not complete, the command is judged
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
) *ToolInspectVerdict {
	if len(command) == 0 {
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
	verdict := a.inspectTrustedToolPolicyCtx(ctx, req, action)
	if verdict == nil || !dispatched || primary.Authoritative() ||
		(commandTool == action.Input.Tool && bytes.Equal(command, action.Input.Args)) {
		return verdict
	}
	input := action.Input
	input.Tool, input.Args = commandTool, command
	findings := dispatchTrustedAction(ctx, trustedActionRequest{
		Input:                     input,
		LegacyText:                string(command),
		Connector:                 action.Connector,
		EnforcementCapable:        action.EnforcementCapable,
		DowngradeReadOnlyDataArgs: action.DowngradeReadOnlyDataArgs,
	})
	return mergeSandboxShellCommandVerdict(a.scannerCfg, firstNonEmpty(req.Connector, action.Connector), verdict, findings)
}

// mergeSandboxShellCommandVerdict raises verdict to the action findings, the
// command judged on its own, decide at the connector's thresholds, when that
// is stronger. The deciding findings replace the call's findings of the same
// rules (there only candidates) and name the reason. A verdict at least as
// strong is returned unchanged.
func mergeSandboxShellCommandVerdict(cfg *config.Config, connectorName string, verdict *ToolInspectVerdict, findings []RuleFinding) *ToolInspectVerdict {
	action := guardrailToolCallActionForFindings(cfg, connectorName, findings, true)
	if strongerGuardrailAction(verdict.Action, action) == verdict.Action {
		return verdict
	}
	deciding := make([]RuleFinding, 0, len(findings))
	for _, finding := range findings {
		if finding.contributesToEnforcement() || finding.contributesToAlertOnly() {
			deciding = append(deciding, finding)
		}
	}
	merged := *verdict
	merged.Action = action
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
