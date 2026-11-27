// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"mvdan.cc/sh/v3/syntax"
)

// withOverBudgetKitProofs adds, to the refusal of a Substrate actor shell
// call past the statement or the reading budget, the key findings its kit
// proved for this exact command in the actor file system (protected_write,
// private_key_read; substrate-1 GAP-0471). The readers that make them on the
// laptop do not run past the budget (rel-1-0-2:GAP-0568), and the cap floor
// pieces cannot follow the actor links, so such a call answered only the
// budget alert where the same statement alone blocks (substrate-1 GAP-1156).
// The same finders as under the budget decide, so the own SSH folder copy
// keeps its alert. Only a call whose command is a proof command runs them:
// every other call past the budget keeps its linear cost. facts is the
// analysis of the call when the caller has one; past the reading budget the
// call is analysed here, only when a proof names it.
func withOverBudgetKitProofs(parent context.Context, request trustedActionRequest, facts *actionfacts.Facts, findings []RuleFinding) []RuleFinding {
	if request.guestProtectedWriteCommand == "" && request.guestKeyReadCommand == "" {
		return findings
	}
	command, ok := trustedBashCommandInput(request.Input)
	write := ok && command == request.guestProtectedWriteCommand
	read := ok && command == request.guestKeyReadCommand
	if !write && !read {
		return findings
	}
	generation := request.generation
	if generation == nil {
		generation = snapshotRulePackGenerationFor(parent, request.Connector)
	}
	if generation == nil {
		return findings
	}
	if facts == nil {
		analyzed := actionfacts.Analyze(request.Input)
		facts = &analyzed
	}
	if write {
		findings = appendTrustedHomeResolvedSSHKeyWriteFinding(findings, generation, request, *facts)
	}
	if read {
		findings = appendTrustedPrivateKeyReaderFinding(findings, generation, request, *facts)
	}
	return withOverBudgetOwnSSHFolderCopyAlert(request, findings)
}

// withOverBudgetOwnSSHFolderCopyAlert keeps the alert of an own SSH folder
// copy (rel-1-0-10:GAP-0018) among the key findings withOverBudgetKitProofs
// added: past the budget the kit cuts the place facts of the words, so the
// copy destination may have no private-place claim, where the laptop, which
// sees its own home, alerts on the same copy. The kit places decide when
// they hold the destination; without them every place of the home outside
// its SSH folder is the owner one, as for an actor call with no kit facts
// (substrate-1 GAP-0922). Only the key findings are lowered, and only to the
// alert: the budget finding still decides the call in its pack.
func withOverBudgetOwnSSHFolderCopyAlert(request trustedActionRequest, findings []RuleFinding) []RuleFinding {
	if !slices.ContainsFunc(findings, overBudgetKitKeyFinding) {
		return findings
	}
	// The whole call is past a bound, so no reading of it proves that
	// nothing opens access to the copy (trustedActionCallOpensAccess): the
	// copy is judged without the helper statements beside it, as the cap
	// floor judges it alone on the laptop. A call that keeps more than the
	// copy is judged on that rest, which fails closed.
	command, ok := trustedBashCommandInput(request.Input)
	if !ok {
		return findings
	}
	rest, ok := ownSSHFolderCopyWithoutHelpers(command, request.Input.ActiveHome)
	if !ok {
		return findings
	}
	judged := bashReadingRequest(request, command, rest)
	if judged.guestHomePlaces == nil {
		judged.guestHomePlaces = request.guestClaimHomePlaces
	}
	if !trustedActionOwnSSHFolderCopy(judged, judged.Input) {
		if request.guestHomePlaces != nil {
			return findings
		}
		judged.guestHomePlaces = &homePlaceSet{byName: true}
		if !trustedActionOwnSSHFolderCopy(judged, judged.Input) {
			return findings
		}
	}
	for index := range findings {
		if overBudgetKitKeyFinding(findings[index]) {
			findings[index].enforcement = findingEnforcementAlertOnly
			if findings[index].RuleID == "persistence.ssh_authorized_keys_command" {
				findings[index].Title = ownSSHFolderCopyTitle
			}
		}
	}
	return findings
}

// ownSSHFolderCopyWithoutHelpers is command without its top-level
// statements that are only the helpers an own SSH folder copy allows beside
// it (echo, printf, true, :, pwd of static words with no redirect, alone or
// joined by &&; trustedActionOwnSSHFolderCopy): they write nothing and open
// no access. ok is false when command does not parse or keeps nothing.
func ownSSHFolderCopyWithoutHelpers(command, home string) (string, bool) {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil {
		return "", false
	}
	home = strings.TrimRight(home, "/")
	var helper func(stmt *syntax.Stmt) bool
	helper = func(stmt *syntax.Stmt) bool {
		if stmt == nil || len(stmt.Redirs) != 0 || stmt.Background || stmt.Coprocess || stmt.Negated {
			return false
		}
		switch cmd := stmt.Cmd.(type) {
		case *syntax.BinaryCmd:
			return cmd.Op == syntax.AndStmt && helper(cmd.X) && helper(cmd.Y)
		case *syntax.CallExpr:
			if len(cmd.Assigns) != 0 || len(cmd.Args) == 0 {
				return false
			}
			for _, arg := range cmd.Args {
				if _, known := hookpaths.StaticWord(arg, home); !known {
					return false
				}
			}
			name, _ := hookpaths.StaticWord(cmd.Args[0], home)
			switch strings.ToLower(path.Base(name)) {
			case "echo", "printf", "true", ":", "pwd":
				return true
			}
		}
		return false
	}
	var kept []string
	printer := syntax.NewPrinter()
	for _, stmt := range file.Stmts {
		if helper(stmt) {
			continue
		}
		var out strings.Builder
		if err := printer.Print(&out, stmt); err != nil {
			return "", false
		}
		kept = append(kept, out.String())
	}
	if len(kept) == 0 {
		return "", false
	}
	return strings.Join(kept, "; "), true
}

// overBudgetKitKeyFinding is a key finding withOverBudgetKitProofs adds.
func overBudgetKitKeyFinding(finding RuleFinding) bool {
	switch finding.RuleID {
	case "persistence.ssh_authorized_keys_command", "PATH-SSH-DIR", "PATH-SSH-KEY", "PATH-WIN-SSH-KEY":
		return true
	}
	return false
}
