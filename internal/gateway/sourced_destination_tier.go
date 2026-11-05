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
	if !known || !sourcedVariableRedirectForm(command, facts.ActiveHome) {
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

// sourcedVariableRedirectForm is the existing three-statement sourced-file
// class: a plain project-file binding, one local source, then a fixed-text
// print redirected through that binding. It does not expand the sourced file
// or add a new target reading; the hook's existing evidence decides known
// protected names.
func sourcedVariableRedirectForm(command, home string) bool {
	if !strings.Contains(command, "source") && !strings.Contains(command, ". ") {
		return false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(shellparse.Reader(command), "")
	if err != nil || len(file.Stmts) != 3 {
		return false
	}
	assignment, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(assignment.Args) != 0 || len(assignment.Assigns) != 1 ||
		len(file.Stmts[0].Redirs) != 0 || file.Stmts[0].Background || file.Stmts[0].Negated {
		return false
	}
	binding := assignment.Assigns[0]
	if binding.Name == nil || binding.Value == nil || binding.Append || binding.Array != nil {
		return false
	}
	value, fixed := hookpaths.StaticWord(binding.Value, home)
	if !fixed || !plainProjectFileName(value) {
		return false
	}
	source, ok := file.Stmts[1].Cmd.(*syntax.CallExpr)
	if !ok || len(source.Args) != 2 || len(source.Assigns) != 0 ||
		len(file.Stmts[1].Redirs) != 0 || file.Stmts[1].Background || file.Stmts[1].Negated ||
		(source.Args[0].Lit() != "." && source.Args[0].Lit() != "source") {
		return false
	}
	sourceName, fixed := hookpaths.StaticWord(source.Args[1], home)
	if !fixed || !plainProjectFileName(strings.TrimPrefix(sourceName, "./")) {
		return false
	}
	writer, ok := file.Stmts[2].Cmd.(*syntax.CallExpr)
	if !ok || len(writer.Args) < 2 || writer.Args[0].Lit() != "echo" ||
		len(writer.Assigns) != 0 || len(file.Stmts[2].Redirs) != 1 ||
		file.Stmts[2].Background || file.Stmts[2].Negated {
		return false
	}
	for _, arg := range writer.Args[1:] {
		if _, fixed := hookpaths.StaticWord(arg, home); !fixed {
			return false
		}
	}
	redirect := file.Stmts[2].Redirs[0]
	if redirect.Op != syntax.AppOut || redirect.N != nil || redirect.Word == nil || len(redirect.Word.Parts) != 1 {
		return false
	}
	quoted, ok := redirect.Word.Parts[0].(*syntax.DblQuoted)
	if !ok || quoted.Dollar || len(quoted.Parts) != 1 {
		return false
	}
	parameter, ok := quoted.Parts[0].(*syntax.ParamExp)
	return ok && parameter.Param != nil && parameter.Param.Value == binding.Name.Value &&
		!parameter.Excl && !parameter.Length && !parameter.Width && !parameter.IsSet &&
		parameter.Index == nil && parameter.Slice == nil && parameter.Exp == nil && parameter.Repl == nil
}

func plainProjectFileName(value string) bool {
	return value != "" && value != "." && value != ".." &&
		!filepath.IsAbs(value) && !strings.ContainsAny(value, "/\\*?[]$~\x00\r\n")
}
