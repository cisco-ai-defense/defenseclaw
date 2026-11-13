// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/toolshape"
)

// Rule ids of the non-shell tool lane (S7, rel-1-0-10:GAP-0016). They live in
// the rule packs (commands.yaml), so severity, title and tags are data.
const (
	mcpSQLDestructiveRuleID = "MCP-SQL-DESTRUCTIVE"
	mcpSQLPrivilegeRuleID   = "MCP-SQL-PRIVILEGE"
	mcpSQLAuditOffRuleID    = "MCP-SQL-AUDIT-OFF"
	mcpSQLCredentialRuleID  = "MCP-SQL-CREDENTIAL"
	mcpSendRedirectRuleID   = "MCP-SEND-REDIRECT"
	mcpSendCollectorRuleID  = "MCP-SEND-COLLECTOR"
	mcpSettingDowngradeID   = "MCP-SETTING-DOWNGRADE"
	mcpCodeDecodeExecRuleID = "MCP-CODE-DECODE-EXEC"

	// maxNonShellPathTwins bounds the file reads one call may have judged.
	maxNonShellPathTwins = 16
)

// nonShellToolFindings reads a non-shell tool call (an MCP or app tool) as
// effects with internal/toolshape and judges them: a path the call names is
// judged as the native file tool on that path would be, so the protected
// target rules apply unchanged; SQL, code, settings and send destinations
// have rules of their own.
//
// The role of each effect is guessed from names, so outside the strict tier
// and managed installs a finding is an alert and never a block. A call the
// table cannot place adds nothing: unknown is not clean, but it alerts only
// where a sensitive target is plausible, and that is the path rules above.
func nonShellToolFindings(ctx context.Context, request trustedActionRequest, findings []RuleFinding) []RuleFinding {
	if !request.EnforcementCapable || ManagedEnterpriseActive() || !nonShellToolApplies(request) {
		return findings
	}
	mapping, err := toolshape.Map(request.Input.Tool, request.Input.Args)
	if err != nil || len(mapping.Effects) == 0 {
		return findings
	}
	generation := snapshotRulePackGenerationFor(ctx, request.Connector)
	if generation == nil {
		return findings
	}
	hard := request.StrictPolicy || request.ManagedInstall
	out := append([]RuleFinding(nil), findings...)
	add := func(ruleID, note string) {
		if slices.ContainsFunc(out, func(f RuleFinding) bool { return f.RuleID == ruleID }) {
			return
		}
		_, rule, ok := trustedActionCatalogRule(generation, ruleID)
		if !ok {
			return
		}
		out = append(out, nonShellFinding(rule, note, mapping.Name, hard))
	}

	primaries := map[string]bool{}
	for _, e := range mapping.Effects {
		if e.Kind == toolshape.KindNetSend && e.Role == toolshape.RolePrimary && e.Host != "" {
			primaries[e.Host] = true
		}
	}
	paths := 0
	seenPath := map[string]bool{}
	for _, e := range mapping.Effects {
		switch e.Kind {
		case toolshape.KindRead, toolshape.KindWrite, toolshape.KindDelete, toolshape.KindList:
			key := string(e.Kind) + "\x00" + e.Path
			if seenPath[key] || paths >= maxNonShellPathTwins {
				continue
			}
			seenPath[key] = true
			paths++
			for _, f := range nonShellPathTwin(ctx, request, e) {
				if slices.ContainsFunc(out, func(x RuleFinding) bool { return x.RuleID == f.RuleID }) {
					continue
				}
				if !hard {
					f.enforcement, f.proof = findingEnforcementAlertOnly, findingProof{}
				}
				f.Title += " (path in MCP tool arguments)"
				out = append(out, f)
			}
		case toolshape.KindSQL:
			for _, class := range e.SQL {
				switch class.Class {
				case toolshape.SQLDrop, toolshape.SQLTruncate, toolshape.SQLDeleteAll:
					add(mcpSQLDestructiveRuleID, "SQL "+class.Class)
				case toolshape.SQLPrivilege:
					add(mcpSQLPrivilegeRuleID, "SQL privilege change")
				case toolshape.SQLAuditOff:
					add(mcpSQLAuditOffRuleID, "SQL turns an audit or logging setting off")
				case toolshape.SQLCredential:
					add(mcpSQLCredentialRuleID, "SQL sets a credential column")
				}
			}
		case toolshape.KindExec:
			if toolshape.DecodeExec(e.Code) {
				add(mcpCodeDecodeExecRuleID, "decoded text is run")
			}
		case toolshape.KindSetting:
			add(mcpSettingDowngradeID, e.Setting)
		case toolshape.KindNetSend:
			if e.Role == toolshape.RoleRedirect && e.Host != "" &&
				!toolshape.LocalHost(e.Host) && !toolshape.PrivateHost(e.Host) && !primaries[e.Host] {
				add(mcpSendRedirectRuleID, "copy or output goes to "+e.Arg)
			}
			if e.Host != "" && nonShellCollectorHost(e.Host) {
				add(mcpSendCollectorRuleID, "sends to a paste or collector host")
			}
		}
	}
	return out
}

// nonShellToolApplies reports a call the typed shell and file-tool paths do
// not already read: not a shell call, not a native tool, not a tool actionfacts
// has argument semantics for.
func nonShellToolApplies(request trustedActionRequest) bool {
	tool := request.Input.Tool
	if tool == "" || request.Input.Command != "" || len(request.Input.Argv) != 0 ||
		toolshape.Native(tool) || actionfacts.KnownTool(tool) || trustedShimArgvTool(tool) {
		return false
	}
	if _, ok := connector.ShellCommandArgs(request.Connector, tool, request.Input.Args); ok {
		return false
	}
	if _, _, ok := connector.TrustedShellArgs(request.Connector, tool, request.Input.Args); ok {
		return false
	}
	return true
}

// nonShellCollectorHost reports a host the sandbox egress feed lists as a
// place anyone can read: a paste site, an anonymous file drop, a webhook
// catcher or a tunnel.
func nonShellCollectorHost(host string) bool {
	feed, err := egress.BuiltinBlocklist()
	if err != nil || feed == nil {
		return false
	}
	match, ok := feed.Match(host)
	if !ok {
		return false
	}
	switch match.Entry.Category {
	case egress.CategoryPasteSite, egress.CategoryFileDrop, egress.CategoryWebhookCatcher:
		return true
	}
	return false
}

func nonShellFinding(rule *PatternRule, note, tool string, hard bool) RuleFinding {
	title := rule.Title
	if note != "" {
		title += " (" + note + ")"
	}
	f := RuleFinding{
		RuleID: rule.ID, Title: title, Severity: rule.Severity, Confidence: rule.Confidence,
		Evidence: tool, Tags: append([]string(nil), rule.Tags...), LineNumber: 1,
	}
	if hard {
		f.enforcement = findingEnforcementAllowed
		f.proof = newExactFallbackFindingProof(rule.ID, true, true, true, true)
	} else {
		f.enforcement = findingEnforcementAlertOnly
	}
	return f
}

// nonShellPathTwin judges the file effect of an MCP call as the native file
// tool of the same effect would be judged, so every protected-target rule of
// the pack applies to the path the MCP argument names.
func nonShellPathTwin(ctx context.Context, request trustedActionRequest, e toolshape.Effect) []RuleFinding {
	tool, args := "Read", map[string]any{"file_path": e.Path}
	switch e.Kind {
	case toolshape.KindWrite:
		tool, args = "Write", map[string]any{"file_path": e.Path, "content": nonShellContentArg(request.Input.Args)}
	case toolshape.KindDelete:
		tool, args = "delete_file", map[string]any{"path": e.Path}
	case toolshape.KindList:
		tool, args = "list_files", map[string]any{"path": e.Path}
	}
	raw, err := json.Marshal(args)
	if err != nil {
		return nil
	}
	twin := request
	twin.Input.Tool, twin.Input.Args = tool, raw
	twin.Input.Command, twin.Input.Argv, twin.Input.ToolResourceIdentity = "", nil, ""
	twin.LegacyText = e.Path
	twin.conflictSource, twin.record, twin.recordTelemetry = nil, nil, nil
	twin.targetMemo, twin.simpleMemo, twin.budget, twin.generation = nil, nil, nil, nil
	twin.parentPatch, twin.simpleCommandPass = nil, false
	twin.ResolvedWriteTargets = nil
	return dispatchTrustedAction(ctx, twin)
}

// nonShellContentArg is the text an MCP write call carries, for the rules
// that read what is written.
func nonShellContentArg(raw json.RawMessage) string {
	var obj map[string]any
	if json.Unmarshal(raw, &obj) != nil {
		return ""
	}
	for _, key := range []string{"content", "contents", "text", "data", "body", "file_text"} {
		if s, ok := obj[key].(string); ok {
			return strings.Clone(s)
		}
	}
	return ""
}
