// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"mvdan.cc/sh/v3/syntax"
)

func balancedOrdinarySSHKeysRequest(request trustedActionRequest) bool {
	input := request.Input
	if len(input.ActiveHome) < 3 || input.ActiveHome[1] != ':' || input.CWD == "" ||
		request.ResolvedWriteTargets[hookpaths.ActionDecisionKey] == hookpaths.ProtectedTargetDecision {
		return false
	}
	if input.Command == "" {
		if !strings.Contains(request.LegacyText, "@'") && !strings.Contains(request.LegacyText, `@"`) &&
			!strings.Contains(strings.ToLower(request.LegacyText), "bash -c ") {
			return false
		}
		input.Command, _ = trustedBashCommandInput(input)
	}
	if !balancedOrdinarySSHKeysCommand(input.Command, input.CWD, input.ActiveHome) {
		return false
	}
	ssh := canonicalSemanticPath(filepath.Join(input.ActiveHome, ".ssh"))
	for operand, resolved := range request.ResolvedWriteTargets {
		if strings.HasPrefix(operand, "\x00") {
			continue
		}
		path := canonicalSemanticPath(resolved)
		if path == ssh {
			return false
		}
		for _, protected := range hookpaths.ProtectedAuthorizedKeysPaths(input.ActiveHome) {
			if path == canonicalSemanticPath(protected) {
				return false
			}
		}
	}
	return true
}

func strictBashListingCommand(request trustedActionRequest) string {
	input := request.Input
	if input.Command == "" {
		if !strings.Contains(request.LegacyText, "bash -c ") {
			return ""
		}
		input.Command, _ = trustedBashCommandInput(input)
	}
	if len(input.ActiveHome) < 3 || input.ActiveHome[1] != ':' ||
		canonicalSemanticPath(input.CWD) != canonicalSemanticPath(input.ActiveHome) ||
		!balancedReadOnlyBashPattern(input.Command, input.ActiveHome) {
		return ""
	}
	return input.Command
}

// balancedOrdinarySSHKeysCommand identifies display-only text and read-only
// wildcard shell work whose Windows path mention is only a possibility.
// The strict tier retains that reading.
func balancedOrdinarySSHKeysCommand(command, cwd, home string) bool {
	if len(command) == 0 || len(command) > 8<<10 {
		return false
	}
	if hookpaths.ProvedDisplayOnlyHereString(command) {
		return true
	}
	if canonicalSemanticPath(cwd) == canonicalSemanticPath(home) && os.Getenv("BASH_ENV") == "" &&
		balancedReadOnlyBashPattern(command, home) {
		return true
	}
	return false
}

// balancedReadOnlyBashPattern uses the existing shell reader for a literal
// Bash child whose statements only read. A wildcard is the uncertain path
// mention; a concrete SSH name still takes the normal protected reading.
func balancedReadOnlyBashPattern(command, home string) bool {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(command)), "bash -c ") {
		return false
	}
	file, err := syntax.NewParser().Parse(strings.NewReader(command), "")
	if err != nil || len(file.Stmts) != 1 {
		return false
	}
	stmt := file.Stmts[0]
	if len(stmt.Redirs) != 0 || stmt.Background || stmt.Coprocess || stmt.Negated {
		return false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) != 3 || !strings.EqualFold(call.Args[0].Lit(), "bash") || call.Args[1].Lit() != "-c" {
		return false
	}
	word := call.Args[2]
	if len(word.Parts) != 1 {
		return false
	}
	var body string
	switch quoted := word.Parts[0].(type) {
	case *syntax.SglQuoted:
		body = quoted.Value
	case *syntax.DblQuoted:
		for _, part := range quoted.Parts {
			literal, ok := part.(*syntax.Lit)
			if !ok {
				return false
			}
			body += literal.Value
		}
	default:
		return false
	}
	if body == "" || !strings.ContainsAny(body, "*?[") ||
		strings.ContainsAny(body, "$`\\%!^\"'\r\n") ||
		strings.Contains(strings.ToLower(body), ".ssh/") ||
		strings.Contains(strings.ToLower(body), "authorized_keys") {
		return false
	}
	return hookpaths.ProvedReadOnlyPOSIXCommand(body, home)
}
