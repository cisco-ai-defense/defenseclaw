// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"os"
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
	if err == nil && (mapping.PageURL != "" || mapping.PageLeaves) {
		notePageNavigation(request, mapping)
	}
	if err != nil || (len(mapping.Effects) == 0 && !mapping.Truncated.Any()) {
		return findings
	}
	generation := snapshotRulePackGenerationFor(ctx, request.Connector)
	if generation == nil {
		return findings
	}
	hard := request.tierEnforces(tierGateManaged)
	out := append([]RuleFinding(nil), findings...)
	// add adds a rule's finding once. An uncertain finding (the call's own
	// account or API host is unknown) alerts in every tier and never blocks.
	add := func(ruleID, note string, uncertain bool) {
		if _, held := readingRuleSlot(out, ruleID); held {
			return
		}
		_, rule, ok := trustedActionCatalogRule(generation, ruleID)
		if !ok {
			return
		}
		out = withReadingFinding(out, nonShellFinding(rule, note, mapping.Name, hard && !uncertain))
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
	twins, wholeTwins := 0, 0
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
			access, resolved := toolshape.PathAccessOf(e.Kind), nonShellResolvePath(request.Input.CWD, e.Path)
			ids := toolshape.PathRules(access, resolved, content)
			// A file of the account's own home, below the active home of the
			// call, as the native file tool reads it (rel-1-0-10:GAP-1002).
			home := actionfacts.Facts{ActiveHome: request.Input.ActiveHome}
			if relative, ok := activeHomeRelative(home, actionfacts.PathFact{Resolved: resolved}); ok {
				ids = append(ids, toolshape.HomePathRules(access, relative, content)...)
			}
			for _, id := range ids {
				// A pack_typed rule is the native twin's to judge (below), as
				// the shell lane judges it as the pack's own finding: a lane
				// finding at the rule's severity judged the MCP call harder
				// than the native tool (rel-1-0-10:GAP-1058, GAP-1069).
				if toolshape.PackTypedPathRule(id) {
					continue
				}
				add(id, "path in MCP tool arguments", false)
			}
			// The value of a path list read whole is another reading of
			// its parts, counted on its own (rel-1-0-10:GAP-0646): a list
			// of 64 paths no longer loses the twin of the whole value.
			counted := &twins
			if e.Whole {
				counted = &wholeTwins
			}
			if *counted >= maxNonShellPathTwins {
				trunc.Hit(bounded.Paths)
				continue
			}
			*counted++
			// The native twin reads a relative path against the session's
			// directory, as the path rules above do (rel-1-0-10:GAP-1071).
			twinEffect := e
			twinEffect.Path = resolved
			for _, f := range nonShellPathTwin(ctx, request, twinEffect, twinContent) {
				if slices.ContainsFunc(out, func(x RuleFinding) bool { return x.RuleID == f.RuleID }) {
					continue
				}
				// For a server and verb the table knows (a file server's
				// read_file) the twin's verdict is the native tool's. For a
				// guessed role the finding is an alert at most outside the
				// strict tier; a finding the native tool leaves detection-only
				// stays so.
				if !hard && !mapping.RoleKnown && !f.Proof.Recorded() {
					f.Proof, f.proof = f.Proof.Advise(), findingProof{}
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
		case toolshape.KindExec, toolshape.KindPageScript:
			if toolshape.DecodeExec(e.Code) {
				add(mcpCodeDecodeExecRuleID, "decoded text is run", false)
			}
			if e.Kind == toolshape.KindPageScript {
				// A script bound (bytes, tokens, sends, definitions, depth) is a
				// bound of this call: judged unknown at least, never clean.
				// 1.0.10 ships the check as an alert in every pack: a proven flow
				// (a literal host that is not the page host, the page known) is not
				// promoted to a block in strict or managed until a corpus that
				// navigates before a script measures it (GAP-0560).
				proven, uncertain, host, caps := pageScriptEgress(request, mapping, e.Code)
				trunc.Merge(caps)
				if proven || uncertain {
					add(pageScriptSessionEgressRuleID, pageScriptNote(proven, host), true)
				}
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
		f.Proof = f.Proof.Enforce()
		f.proof = newExactFallbackFindingProof(rule.ID, true, true, true, true)
	} else {
		f.Proof = f.Proof.Advise()
	}
	return f
}

// nonShellNamesOtherAccountCredential reports whether the call names a home
// credential file (otherHomeCredentialFile) of an account home that is not the
// active one. With no active home nothing tells the two apart, and the call
// keeps the findings it carries.
func nonShellNamesOtherAccountCredential(facts actionfacts.Facts) bool {
	if canonicalSemanticPath(facts.ActiveHome) == "" {
		return false
	}
	for _, candidate := range facts.Paths {
		if _, own := activeHomeRelative(facts, candidate); own {
			continue
		}
		shape, ok := actionfacts.MatchCredentialFileShape(canonicalSemanticPath(semanticPathValue(candidate)))
		if ok && otherHomeCredentialFile(facts, candidate, shape.Class, "") {
			return true
		}
	}
	return false
}

// nonShellFindingStronger reports whether candidate is a stronger finding of
// its rule than existing: it may enforce where existing only alerts, or it
// carries a higher severity.
func nonShellFindingStronger(candidate, existing RuleFinding) bool {
	if candidate.contributesToEnforcement() && !existing.contributesToEnforcement() {
		return true
	}
	if existing.contributesToEnforcement() && !candidate.contributesToEnforcement() {
		return false
	}
	return guardrailSeverityRank(candidate.Severity) > guardrailSeverityRank(existing.Severity)
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
// applyPatchFileTexts is the text an apply_patch call writes: per file the
// envelope adds or updates (by the path it names), the lines it adds, and
// all of them joined. Read as a write tool's content, the envelope named no
// content, so a rule that reads what is written (a system schedule line,
// CMD-PERSIST-SYSTEM-SCHEDULE) never matched a Codex or OpenCode patch that
// Claude Code's Write of the same file raises (rel-1-0-10:GAP-0780).
func applyPatchFileTexts(raw json.RawMessage) (byPath map[string]string, all string) {
	parsed, _ := decodeCodeGuardArgsObject(raw)
	if parsed == nil {
		return nil, ""
	}
	text, _ := exactCodeGuardStringField(parsed, codeGuardBestEffortObject(parsed),
		"command", "cmd", "patch", "patchText", "patch_text", "input")
	files, _ := codeGuardPatchFiles(text)
	byPath = make(map[string]string, len(files))
	parts := make([]string, 0, len(files))
	for _, file := range files {
		if prior, ok := byPath[file.path]; ok {
			byPath[file.path] = prior + "\n" + file.content
		} else {
			byPath[file.path] = file.content
		}
		parts = append(parts, file.content)
	}
	return byPath, strings.Join(parts, "\n")
}

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
//
// A list (&&, ||, ;) is judged as a whole and statement by statement, and
// the findings are the union. The facts of the whole list leave a "~/"
// operand dynamic, because an earlier statement may change HOME, so a read
// of a home file by one statement had no path fact there and adding any
// other statement dropped its finding (rel-1-0-10:GAP-0951). The statements
// come from the walk the rule dispatch judges its children with
// (actionfacts.SimpleCommands), which follows HOME, cd and the variables of
// the list, and each is judged as the same statement sent alone.
func shellToolFindings(ctx context.Context, request trustedActionRequest, findings []RuleFinding) []RuleFinding {
	if !request.EnforcementCapable || ManagedEnterpriseActive() || nonShellLaneShadow(ctx) {
		return findings
	}
	// A shell call is read by its command; a native file tool (Read, Write,
	// Edit, ...) by its arguments, so the same path rules judge the native
	// tool and the MCP twin of it alike (an MCP call is never judged harder).
	command, isShell := trustedBashCommandInput(request.Input)
	text := command
	var patchTexts map[string]string
	if !isShell {
		if !actionfacts.PathTool(request.Input.Tool) {
			return findings
		}
		text = nonShellContentOf(request.Input.Args)
		if codeGuardPatchTool(request.Input.Tool) {
			patchTexts, text = applyPatchFileTexts(request.Input.Args)
		}
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
	hard := request.tierEnforces(tierGateManaged)
	otherAccount := nonShellNamesOtherAccountCredential(facts)
	out := append([]RuleFinding(nil), findings...)
	// A finding of the lane is merged as the dispatch merges the finding of a
	// statement (withSimpleCommandFindings): it replaces a weaker finding of
	// the same rule and never a stronger one. Skipping every rule id already
	// in the findings let a detection-only finding of the dispatch hide the
	// lane's enforcing one (rel-1-0-10:GAP-0995).
	// merge adds the lane's finding of ruleID; token says whether the lane
	// derives it from a developer-token file of the active home itself
	// (ownDeveloperTokenAccess), and whether the call reads it or reaches it another way.
	// input and facts are what the finding was read from (the call, or one statement of it).
	merge := func(input actionfacts.Input, facts actionfacts.Facts, ruleID, note string, token ownTokenAccess) {
		_, rule, ok := trustedActionCatalogRule(generation, ruleID)
		if !ok {
			return
		}
		finding := nonShellFinding(rule, note, request.Input.Tool, hard)
		if toolshape.PackTypedPathRule(ruleID) {
			if finding, ok = packTypedPathFinding(generation, request, input, facts, rule, note); !ok {
				return
			}
		}
		if index := slices.IndexFunc(out, func(f RuleFinding) bool { return f.RuleID == ruleID }); index >= 0 {
			// When the call names a credential file in another account's
			// home, a finding of the same rule that is stronger by
			// enforcement or severity replaces the one the call carries: the
			// regex fallback judges that home at a lower severity and
			// alert-only, so an upload of another account's .git-credentials
			// or .netrc was weaker than an upload of one's own
			// (rel-1-0-10:GAP-0834, GAP-0835).
			//
			// A call that reaches the active home's own .git-credentials,
			// .netrc or .pgpass other than by reading it (a copy, a find that
			// hands it to a program) keeps the verdict rel gives it: the
			// catalog finding of the rule, CRITICAL, a block in strict and
			// managed installs. Since a copy counts as a read of its source for
			// the credential-file rules (b1d66c243c), the call carries the
			// typed owner's alert of the read, which the lane kept, so a copy
			// fell to alert MEDIUM (HIGH for .pgpass) and to allow in the
			// permissive pack. The GAP-0888 ruling covers reads only, and of
			// these files the tier of one's own AWS and kube files is not
			// extended to a copy (lead, 2026-11-16).
			if (otherAccount || token == ownTokenOther) && nonShellFindingStronger(finding, out[index]) {
				out[index] = finding
				return
			}
			// A read of the active home's own .git-credentials, .netrc or
			// .pgpass keeps the alert the call carries, the tier rel gives
			// it, in every pack (rel-1-0-10:GAP-0888). The rank merge below
			// would make it a block in strict and managed installs.
			if token == ownTokenRead && !otherAccount && out[index].contributesToAlertOnly() {
				return
			}
		}
		out = withSimpleCommandFindings(out, []RuleFinding{finding})
	}
	add := func(input actionfacts.Input, facts actionfacts.Facts, ruleID, note string) {
		merge(input, facts, ruleID, note, ownTokenNone)
	}
	judge := func(input actionfacts.Input, facts actionfacts.Facts, command, text string) {
		if isShell {
			for _, id := range toolshape.TextRules(command) {
				add(input, facts, id, "")
			}
			for _, c := range facts.Commands {
				for _, id := range toolshape.CommandRules(c.Program, c.Argv) {
					add(input, facts, id, "")
				}
				// The program a chain of static prefix wrappers runs with its
				// argv unchanged is judged by its own words too
				// (taskset 1 sudo chmod u+s F is chmod u+s F; GAP-1461).
				if program, argv, ok := actionfacts.ExactWrapperChild(c); ok {
					for _, id := range toolshape.CommandRules(program, argv) {
						add(input, facts, id, "")
					}
				}
			}
		}
		for _, p := range facts.Paths {
			path := firstNonEmpty(p.Resolved, p.Normalized, p.Value)
			text := text
			if fileText, ok := patchTexts[p.Value]; ok {
				text = fileText
			}
			own := ownDeveloperTokenAccess(facts, p, path)
			ids := append(toolshape.PathRules(string(p.Access), path, text), homePathRuleIDs(facts, p, text)...)
			for _, id := range ids {
				// A link to /dev/null in a unit folder masks the unit: it stops
				// what runs at boot or login, it does not start anything.
				if id == "CMD-PERSIST-SYSTEM-SCHEDULE" && linksToDevNull(facts, p.CommandID) {
					continue
				}
				merge(input, facts, id, "", own)
			}
			// The developer-token files of an account's home (the credentials
			// table's class of PATH-GIT-CREDS) are read by the native file tools as
			// the shell and MCP lanes read them (rel-1-0-10:GAP-0816). The class
			// comes from the one table, so each branch's table decides which names
			// are in it; the home is found by position.
			if p.Access == actionfacts.PathAccessRead && developerTokenFileOfAccountHome(path) {
				merge(input, facts, "PATH-GIT-CREDS", "", own)
			}
		}
	}
	judge(request.Input, facts, command, text)
	if isShell {
		for _, simple := range request.simpleMemo.commands(request.Input, facts) {
			// A failed or capped reading is the dispatch's to judge (the unknown
			// tier), an opaque value or an inert output adds no evidence, and a
			// login guess only proves a state write, never a rule over its words
			// (actionfacts.SimpleCommand).
			if simple.EvaluationFailure != "" || simple.OpaqueValueAssignment ||
				simple.LiteralOutputOnly || simple.LoginGuess {
				continue
			}
			child := request.Input
			child.Command, child.Args, child.Argv = simple.Text, nil, nil
			child.CWD = simple.CWD
			if simple.AbsoluteOnly || child.CWD == "" {
				child.CWD = request.Input.CWD
			}
			judge(child, actionfacts.Analyze(child), simple.Text, simple.Text)
		}
		// A bash here-string (CMD <<< WORD) is a syntax error to the POSIX
		// analysis, so the call has no paths and no statements: the lane
		// reads its twin printf '%s\n' WORD | CMD too, as the dispatch does
		// (hereStringReadingTwinRequest). Without it a cd, a here-string and
		// then a write in the cd folder lost the path rules of the write
		// (a system schedule, a launch agent, the git config, the shadow
		// read) that the one-step form gets (rel-1-0-10:GAP-1083).
		if twin, ok := hereStringReadingTwinRequest(request, facts); ok {
			out = shellToolFindings(ctx, twin, out)
		}
		// An xargs fed fixed words (echo|printf WORDS | xargs CMD) runs CMD
		// with them, which the call's facts do not model: the lane reads
		// that call as typed too, so a credential file copied through xargs
		// gets the path rules of the copy (rel-1-0-10:GAP-0997).
		for _, twin := range xargsStaticInputTwinRequests(request) {
			out = shellToolFindings(ctx, twin, out)
		}
	}
	// A sandbox call's relative operands name files in the guest's own
	// working directory, where "~" is the guest home: the request's directory
	// is none in copy mode and the host mount in mount mode. The rules on a
	// file of the home read the call placed there too (the lexical reading
	// the semantic owners judge, sandboxGuestPlacedInput), so `printf ... >
	// .config/systemd/user/x.service` from /sandbox gets the laptop's verdict
	// (rel-1-0-10:GAP-1002). It runs for the native file tools too.
	if guest, ok := sandboxGuestPlacedInput(request, facts); ok {
		guestFacts := request.guestMemo.analyze(guest)
		for _, p := range guestFacts.Paths {
			for _, id := range homePathRuleIDs(guestFacts, p, text) {
				if id == "CMD-PERSIST-SYSTEM-SCHEDULE" && linksToDevNull(guestFacts, p.CommandID) {
					continue
				}
				add(guest, guestFacts, id, "")
			}
		}
	}
	return out
}

// packTypedPathFinding is the lane's finding of a pack_typed path rule
// (toolshape.PackTypedPathRule): the finding the pack's own owner of the rule
// gives, in every tier. The rule's exact fallback contract decides whether the
// call proves it (filterExactFallbackFindings; for PATH-ETC-SHADOW,
// shadowContentAccessPrerequisite: a mutation, or a read that is not a
// targeted account lookup), and the boundary every catalog finding of a
// trusted action passes judges it (finalizeTrustedActionFindings) on the facts
// the lane read: a local read of /etc/shadow is an advisory MEDIUM (an alert,
// below the permissive alert threshold) in every pack and on managed
// installs, a mutation keeps the rule's tier. So a call that reaches the file
// after a cd (cd /etc && cat shadow) gets the verdict rel gives the one-step
// spelling in all five tiers. A lane finding at the rule's severity alerted
// in permissive (rel-1-0-10:GAP-1058) and, in strict and managed installs,
// blocked the reads rel alerts on and the account lookup rel allows
// (GAP-1069). ok is false when no finding of the rule is left.
func packTypedPathFinding(generation *compiledRulePackCategories, request trustedActionRequest, input actionfacts.Input, facts actionfacts.Facts, rule *PatternRule, note string) (RuleFinding, bool) {
	typed := nonShellFinding(rule, note, request.Input.Tool, true)
	proven := filterExactFallbackFindings([]RuleFinding{typed}, input, facts, request.EnforcementCapable)
	if len(proven) == 0 {
		return RuleFinding{}, false
	}
	request.Input = input
	for _, finding := range finalizeTrustedActionFindings(generation, request, facts, proven) {
		if finding.RuleID == rule.ID {
			return finding, true
		}
	}
	return RuleFinding{}, false
}

// homePathRuleIDs are the table rules on a file of the account's own home
// (toolshape.HomePathRules) that path fact p matches, read below the active
// home of the call (activeHomeRelative) and never below a home guessed from
// the shape of the path, so a sandbox actor (home /sandbox) and the laptop
// get one verdict (rel-1-0-10:GAP-1002).
func homePathRuleIDs(facts actionfacts.Facts, p actionfacts.PathFact, text string) []string {
	relative, ok := activeHomeRelative(facts, p)
	if !ok {
		return nil
	}
	return toolshape.HomePathRules(string(p.Access), relative, text)
}

// linksToDevNull reports an ln whose source is /dev/null: the link it makes
// masks its name (systemctl mask), a way to turn a unit off.
func linksToDevNull(facts actionfacts.Facts, commandID int64) bool {
	for _, command := range facts.Commands {
		if command.ID != commandID || path.Base(command.Program) != "ln" {
			continue
		}
		for _, word := range argvOperands(command.Argv) {
			if word == os.DevNull {
				return true
			}
		}
	}
	return false
}

// ownTokenAccess is how a call reaches a developer-token file of the active
// home itself (ownDeveloperTokenAccess).
type ownTokenAccess int

const (
	// ownTokenNone: no such file, or a file of another account's home.
	ownTokenNone ownTokenAccess = iota
	// ownTokenRead: the call reads the file (cat, a native Read).
	ownTokenRead
	// ownTokenOther: the call reaches it another way: the source of a copy
	// (cp, rsync, install), a starting point a find hands to a program.
	ownTokenOther
)

// ownDeveloperTokenAccess reports whether a path fact names a file of the
// developer-token class (developerTokenFileOfAccountHome) in the active home
// of the call itself (activeHomeRelative), not in another account's home, and
// whether its command reads it or reaches it another way.
func ownDeveloperTokenAccess(facts actionfacts.Facts, p actionfacts.PathFact, path string) ownTokenAccess {
	if !developerTokenFileOfAccountHome(path) {
		return ownTokenNone
	}
	if _, own := activeHomeRelative(facts, p); !own {
		return ownTokenNone
	}
	if command, ok := integrityCommandByID(facts, p.CommandID); ok &&
		(!hasOperation(command, actionfacts.OperationRead) || hasOperation(command, actionfacts.OperationCopy)) {
		return ownTokenOther
	}
	return ownTokenRead
}

// developerTokenFileOfAccountHome reports an absolute path that is a file of
// the developer-token class directly in an account home, found by its position
// (isRecognizedHomeRoot: /root, /home/<acct>, /Users/<acct>, <drive>:/Users/<acct>)
// and never by the name of a folder deeper in the path: a project folder that
// is only called home, homes or users, and a fixture tree, hold no account home
// (rel-1-0-10:GAP-0836).
func developerTokenFileOfAccountHome(value string) bool {
	value = canonicalSemanticPath(value)
	if !isAbsoluteSemanticPath(value) || integrityPathHasFixtureSegment(value) {
		return false
	}
	for dir := path.Dir(value); dir != "/" && dir != "." && dir != ""; dir = path.Dir(dir) {
		if !isRecognizedHomeRoot(dir) {
			continue
		}
		relative := strings.TrimPrefix(value, dir+"/")
		shape, ok := actionfacts.MatchCredentialFileShape(relative)
		return ok && shape.Class == actionfacts.CredentialFileDeveloperToken && shape.Relative == relative
	}
	return false
}
