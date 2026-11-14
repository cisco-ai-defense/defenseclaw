// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"path"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
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

	// sqlMutationOwnerRuleID is the exact SQL-mutation owner (actionfacts) that
	// already judges structured SQL tool calls.
	sqlMutationOwnerRuleID = "impact.sql_destructive_mutation"

	// maxNonShellPathTwins bounds the file reads one call may have judged.
	maxNonShellPathTwins = 64 // twin dispatches of one call (bounded.Paths); the table's path rules read every path
)

// nonShellLaneShadow is the one switch of the whole non-shell lane (the MCP
// effects and the table rules on shell and native file-tool calls):
// guardrail.cascade.lanes.nonshell, on, shadow or off (default on), read
// through the cascade lane registry (config.CascadeLanes.NonShellMode). Only on
// is live: in shadow and in off the lane computes nothing and adds nothing, so
// the verdicts are those of rel/1.0.10. The configuration is the request's (its
// pinned generation, or its profile's); with none the lane is on.
func nonShellLaneShadow(ctx context.Context) bool {
	cfg := requestPolicyConfig(ctx)
	return cfg != nil && cfg.Guardrail.Cascade.Lanes.NonShellMode() != config.CascadeLaneOn
}

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
func nonShellToolFindings(ctx context.Context, request trustedActionRequest, findings []RuleFinding, mcpServer string) []RuleFinding {
	if !request.EnforcementCapable || ManagedEnterpriseActive() || nonShellLaneShadow(ctx) || !nonShellToolApplies(request, mcpServer) {
		return findings
	}
	mapping, err := toolshape.Map(request.Input.Tool, request.Input.Args, mcpServer)
	if err != nil || (len(mapping.Effects) == 0 && !mapping.Truncated.Any()) {
		return findings
	}
	generation := snapshotRulePackGenerationFor(ctx, request.Connector)
	if generation == nil {
		return findings
	}
	hard := request.StrictPolicy || request.ManagedInstall
	out := append([]RuleFinding(nil), findings...)
	// add adds a rule's finding once. An uncertain finding (the call's own
	// account or API host is unknown) alerts in every tier and never blocks.
	add := func(ruleID, note string, uncertain bool) {
		if slices.ContainsFunc(out, func(f RuleFinding) bool { return f.RuleID == ruleID }) {
			return
		}
		_, rule, ok := trustedActionCatalogRule(generation, ruleID)
		if !ok {
			return
		}
		out = append(out, nonShellFinding(rule, note, mapping.Name, hard && !uncertain))
	}
	// The hosts the call itself names for its own parties: its primary
	// recipients and request URLs, and its own account when it says which.
	own := map[string]bool{}
	for _, e := range mapping.Effects {
		if (e.Role == toolshape.RolePrimary || e.Role == toolshape.RoleURL) && e.Host != "" {
			own[e.Host] = true
		}
	}

	// One reading of the call's text, shared by every path effect: the path
	// rules that read what is written, and the first write twin.
	content := mapping.Content
	twinContent := content
	// A bound that cut the walk short leaves part of the call unread: the call
	// is judged unknown at least (bounded.Floor), never clean. What was read
	// before the bound is judged as always.
	var trunc bounded.Truncated
	trunc.Merge(mapping.Truncated)
	twins := 0
	seenPath := map[string]bool{}
	for _, e := range mapping.Effects {
		switch e.Kind {
		case toolshape.KindRead, toolshape.KindWrite, toolshape.KindDelete, toolshape.KindList:
			key := string(e.Kind) + "\x00" + e.Path
			if seenPath[key] {
				continue
			}
			seenPath[key] = true
			// The table's rules are cheap: every path effect is read, with a
			// relative path resolved against the session's directory.
			for _, id := range toolshape.PathRules(toolshape.PathAccessOf(e.Kind), nonShellResolvePath(request.Input.CWD, e.Path), content) {
				add(id, "path in MCP tool arguments", false)
			}
			if twins >= maxNonShellPathTwins {
				trunc.Hit(bounded.Paths)
				continue
			}
			twins++
			for _, f := range nonShellPathTwin(ctx, request, e, twinContent) {
				if slices.ContainsFunc(out, func(x RuleFinding) bool { return x.RuleID == f.RuleID }) {
					continue
				}
				// For a server and verb the table knows (a file server's
				// read_file) the twin's verdict is the native tool's. For a
				// guessed role the finding is an alert at most outside the
				// strict tier; a finding the native tool leaves detection-only
				// stays so.
				if !hard && !mapping.RoleKnown && f.enforcement != findingEnforcementDetectionOnly {
					f.enforcement, f.proof = findingEnforcementAlertOnly, findingProof{}
				}
				f.Title += " (path in MCP tool arguments)"
				out = append(out, f)
			}
			if e.Kind == toolshape.KindWrite {
				// The body was scanned once, with the first write; the other
				// twins judge the path only.
				twinContent = ""
			}
		case toolshape.KindSQL:
			for _, class := range e.SQL {
				switch class.Class {
				case toolshape.SQLDrop, toolshape.SQLTruncate, toolshape.SQLDeleteAll:
					// The exact SQL-mutation owner already judged this call.
					if !slices.ContainsFunc(out, func(f RuleFinding) bool { return f.RuleID == sqlMutationOwnerRuleID }) {
						add(mcpSQLDestructiveRuleID, "SQL "+class.Class, false)
					}
				case toolshape.SQLPrivilege:
					add(mcpSQLPrivilegeRuleID, "SQL privilege change", false)
				case toolshape.SQLAuditOff:
					add(mcpSQLAuditOffRuleID, "SQL turns an audit or logging setting off", false)
				case toolshape.SQLCredential:
					add(mcpSQLCredentialRuleID, "SQL sets a credential column", false)
				}
			}
		case toolshape.KindExec:
			if toolshape.DecodeExec(e.Code) {
				add(mcpCodeDecodeExecRuleID, "decoded text is run", false)
			}
		case toolshape.KindSetting:
			add(mcpSettingDowngradeID, e.Setting, false)
		case toolshape.KindNetSend, toolshape.KindNetFetch:
			// A copy or output field that names a host outside the call's own
			// parties (its recipients, its request URL, its own account) is a
			// redirect. When the call does not say whose account it is the
			// finding is uncertain: an alert in every tier, never a block. A
			// paste, file-drop or webhook-catcher host is a collector for a
			// fetch as for a send.
			// A callback URL is judged against the call's own request URLs only;
			// with none to compare, it has no baseline and adds nothing.
			if e.Role == toolshape.RoleCallback && len(own) > 0 && e.Host != "" &&
				!toolshape.LocalHost(e.Host) && !toolshape.PrivateHost(e.Host) && !own[e.Host] {
				add(mcpSendRedirectRuleID, "callback goes to "+e.Arg, true)
			}
			if e.Role == toolshape.RoleRedirect && e.Host != "" &&
				!toolshape.LocalHost(e.Host) && !toolshape.PrivateHost(e.Host) &&
				!own[e.Host] {
				// The caller names its own account, so nothing the call says
				// excuses a copy: the finding is uncertain, an alert in every tier.
				add(mcpSendRedirectRuleID, "copy or output goes to "+e.Arg, true)
			}
			if e.Host != "" && nonShellCollectorHost(e.Host) {
				add(mcpSendCollectorRuleID, "reaches a paste, file-drop or webhook-catcher host", false)
			}
		}
	}
	// Every cap the reading reached counts: the limit finding, at least the
	// unknown tier of the pack (alert in default, permissive and managed
	// default; block in strict).
	out = withBoundedTruncation(out, trunc.Set(), request)
	return out
}

// nonShellResolvePath makes a relative path absolute against the session's
// working directory (lexically); an absolute, home or empty value is returned
// as it is.
func nonShellResolvePath(cwd, p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	if p == "" || cwd == "" || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~") || len(p) > 1 && p[1] == ':' {
		return p
	}
	return path.Clean(strings.ReplaceAll(cwd, `\`, "/") + "/" + p)
}

// nonShellToolApplies reports a call the typed shell and file-tool paths do
// not already read: not a shell call and not a tool actionfacts has argument
// semantics for. A tool the connector reports under an MCP server is never one
// of the agent's own tools, whatever its bare name.
func nonShellToolApplies(request trustedActionRequest, mcpServer string) bool {
	tool := request.Input.Tool
	if tool == "" || request.Input.Command != "" || len(request.Input.Argv) != 0 || trustedShimArgvTool(tool) {
		return false
	}
	if mcpServer == "" && actionfacts.KnownTool(tool) && !toolshape.HasFileURIArg(request.Input.Args) {
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
func nonShellPathTwin(ctx context.Context, request trustedActionRequest, e toolshape.Effect, content string) []RuleFinding {
	tool, args := "Read", map[string]any{"file_path": e.Path}
	switch e.Kind {
	case toolshape.KindWrite:
		tool, args = "Write", map[string]any{"file_path": e.Path, "content": content}
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

// nonShellContentOf is the text a native file tool call writes, read the way
// the MCP lane reads it (nested values and edit lists included).
func nonShellContentOf(raw json.RawMessage) string {
	m, err := toolshape.Map("write", raw, "")
	if err != nil {
		return ""
	}
	return m.Content
}

// shellToolFindings judges a shell call with the path and command rules of
// the tool-shape table, in Go on the parsed ActionFacts (the rule catalog's
// CEL budget is spent). Like the MCP lane, outside the strict tier and
// managed installs a finding is an alert. A call without a word any rule
// needs is not parsed again.
func shellToolFindings(ctx context.Context, request trustedActionRequest, findings []RuleFinding) []RuleFinding {
	if !request.EnforcementCapable || ManagedEnterpriseActive() || nonShellLaneShadow(ctx) {
		return findings
	}
	// A shell call is read by its command; a native file tool (Read, Write,
	// Edit, ...) by its arguments, so the same path rules judge the native
	// tool and the MCP twin of it alike (an MCP call is never judged harder).
	command, isShell := trustedBashCommandInput(request.Input)
	text := command
	if !isShell {
		if !actionfacts.PathTool(request.Input.Tool) {
			return findings
		}
		text = nonShellContentOf(request.Input.Args)
		if !toolshape.ShellCandidate(string(request.Input.Args)) {
			return findings
		}
	} else if !toolshape.ShellCandidate(command) {
		return findings
	}
	generation := snapshotRulePackGenerationFor(ctx, request.Connector)
	if generation == nil {
		return findings
	}
	request.Input.CWD = managedClientCWD(ctx, request.Input.CWD, request.ResolvedWriteTargets)
	facts := actionfacts.Analyze(request.Input)
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
		out = append(out, nonShellFinding(rule, note, request.Input.Tool, hard))
	}
	if isShell {
		for _, id := range toolshape.TextRules(command) {
			add(id, "")
		}
		for _, c := range facts.Commands {
			for _, id := range toolshape.CommandRules(c.Program, c.Argv) {
				add(id, "")
			}
		}
	}
	for _, p := range facts.Paths {
		path := firstNonEmpty(p.Resolved, p.Normalized, p.Value)
		for _, id := range toolshape.PathRules(string(p.Access), path, text) {
			add(id, "")
		}
	}
	return out
}
