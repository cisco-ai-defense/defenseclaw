// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// balancedSourcedDestination leaves a sourced file's unresolved destination
// to the balanced hook policy when the existing readers found no protected
// target. The strict tier retains the conservative finding. A managed hook
// cannot use this tier decision because its gateway cannot verify that a
// sourced file under the hidden home still has the client's earlier contents.
func balancedSourcedDestination(request trustedActionRequest, facts actionfacts.Facts) bool {
	if !request.balancedSourceDestination || !request.EnforcementCapable || request.ProtectedHomeHook ||
		(request.Connector != "claudecode" && request.Connector != "codex") ||
		!trustedPOSIXShellCall(request.Input, facts) ||
		facts.ActiveHome == "" {
		return false
	}
	cwd := request.Input.CWD
	if !filepath.IsAbs(cwd) {
		return false
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known || !unresolvedVariableRedirectForm(command, facts.ActiveHome) {
		return false
	}
	if request.targetMemo.ActionCommandDecisionWithDialectAndGlobFacts(
		command, cwd, facts.ActiveHome, request.Input.DialectHint,
		clientGlobFacts(request)) != "" {
		return false
	}
	if hookpaths.UnprovenProtectedWrite(command, cwd, facts.ActiveHome) != "" {
		return false
	}
	return true
}

// unresolvedVariableRedirectForm identifies a variable destination whose
// command text supplies only ordinary project-file candidates. The unresolved
// part is a local source. The path reader above still judges
// the current source file and every named link before the tier can apply.
func unresolvedVariableRedirectForm(command, home string) bool {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(shellparse.Reader(command), "")
	if err != nil || len(file.Stmts) < 3 {
		return false
	}
	name, ok := variableRedirectWriter(file.Stmts[len(file.Stmts)-1], home)
	if !ok {
		return false
	}
	binding, uncertainty := false, false
	for _, stmt := range file.Stmts[:len(file.Stmts)-1] {
		if !plainVariableStatement(stmt) || len(stmt.Redirs) != 0 {
			return false
		}
		switch call := stmt.Cmd.(type) {
		case *syntax.CallExpr:
			if len(call.Args) == 0 {
				if !plainVariableBinding(call, name, home) {
					return false
				}
				binding = true
				continue
			}
			if len(call.Assigns) != 0 {
				return false
			}
			switch call.Args[0].Lit() {
			case ".", "source":
				if !binding || len(call.Args) != 2 {
					return false
				}
				path, fixed := hookpaths.StaticWord(call.Args[1], home)
				if !fixed || !plainProjectPath(strings.TrimPrefix(path, "./")) {
					return false
				}
				uncertainty = true
			case ":":
				if len(call.Args) != 1 {
					return false
				}
			default:
				return false
			}
		default:
			return false
		}
	}
	return binding && uncertainty
}

func plainVariableStatement(stmt *syntax.Stmt) bool {
	return stmt != nil && stmt.Cmd != nil && !stmt.Background &&
		!stmt.Coprocess && !stmt.Disown && !stmt.Negated
}

func plainVariableBinding(call *syntax.CallExpr, name, home string) bool {
	if len(call.Assigns) != 1 {
		return false
	}
	a := call.Assigns[0]
	if a.Name == nil || a.Name.Value != name || a.Value == nil ||
		a.Append || a.Array != nil || a.Index != nil {
		return false
	}
	value, fixed := hookpaths.StaticWord(a.Value, home)
	return fixed && plainProjectPath(value)
}

func variableRedirectWriter(stmt *syntax.Stmt, home string) (string, bool) {
	if !plainVariableStatement(stmt) || len(stmt.Redirs) != 1 {
		return "", false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) < 2 {
		return "", false
	}
	switch call.Args[0].Lit() {
	case "echo", "printf":
	default:
		return "", false
	}
	for _, arg := range call.Args[1:] {
		if _, fixed := hookpaths.StaticWord(arg, home); !fixed {
			return "", false
		}
	}
	redirect := stmt.Redirs[0]
	if redirect.Op != syntax.AppOut || redirect.N != nil ||
		redirect.Word == nil || len(redirect.Word.Parts) != 1 {
		return "", false
	}
	part := redirect.Word.Parts[0]
	if quoted, ok := part.(*syntax.DblQuoted); ok {
		if quoted.Dollar || len(quoted.Parts) != 1 {
			return "", false
		}
		part = quoted.Parts[0]
	}
	parameter, ok := part.(*syntax.ParamExp)
	if !ok || parameter.Param == nil || parameter.Excl || parameter.Length ||
		parameter.Width || parameter.IsSet || parameter.Index != nil ||
		parameter.Slice != nil || parameter.Exp != nil || parameter.Repl != nil {
		return "", false
	}
	return parameter.Param.Value, true
}

func plainProjectPath(value string) bool {
	if value == "" || filepath.IsAbs(value) ||
		strings.ContainsAny(value, "\\*?[]$~\x00\r\n \t;&|><'\"") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}
