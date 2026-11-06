// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"io"
	"os"
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
// requires a current source view that its hidden home does not provide.
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
	root, err := os.OpenRoot(cwd)
	if err != nil {
		return false
	}
	defer root.Close()
	command, known := trustedBashCommandInput(request.Input)
	if !known || !unresolvedVariableRedirectForm(command, cwd, facts.ActiveHome, root) {
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
func unresolvedVariableRedirectForm(command, cwd, home string, root *os.Root) bool {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(shellparse.Reader(command), "")
	if err != nil || len(file.Stmts) < 3 {
		return false
	}
	name, quoted, ok := variableRedirectWriter(file.Stmts[len(file.Stmts)-1], home)
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
				if !plainVariableBinding(call, name, cwd, home, quoted, root) {
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
				if !fixed || !knownProjectDestination(path, cwd, true, root) ||
					!currentProjectSourceOrdinary(path, cwd, home, name, quoted, root) {
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

func plainVariableBinding(call *syntax.CallExpr, name, cwd, home string, quoted bool, root *os.Root) bool {
	if len(call.Assigns) != 1 {
		return false
	}
	a := call.Assigns[0]
	if a.Name == nil || a.Name.Value != name || a.Value == nil ||
		a.Append || a.Array != nil || a.Index != nil {
		return false
	}
	value, fixed := hookpaths.StaticWord(a.Value, home)
	return fixed && knownProjectDestination(value, cwd, quoted, root)
}

func variableRedirectWriter(stmt *syntax.Stmt, home string) (string, bool, bool) {
	if !plainVariableStatement(stmt) || len(stmt.Redirs) != 1 {
		return "", false, false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || !fixedOutputCommand(call, home) {
		return "", false, false
	}
	for _, arg := range call.Args {
		if _, fixed := hookpaths.StaticWord(arg, home); !fixed {
			return "", false, false
		}
	}
	redirect := stmt.Redirs[0]
	if (redirect.Op != syntax.AppOut && redirect.Op != syntax.RdrOut) || redirect.N != nil ||
		redirect.Word == nil || len(redirect.Word.Parts) != 1 {
		return "", false, false
	}
	part := redirect.Word.Parts[0]
	quotedDestination := false
	if quoted, ok := part.(*syntax.DblQuoted); ok {
		if quoted.Dollar || len(quoted.Parts) != 1 {
			return "", false, false
		}
		part = quoted.Parts[0]
		quotedDestination = true
	}
	parameter, ok := part.(*syntax.ParamExp)
	if !ok || parameter.Param == nil || parameter.Excl || parameter.Length ||
		parameter.Width || parameter.IsSet || parameter.Index != nil ||
		parameter.Slice != nil || parameter.Exp != nil || parameter.Repl != nil {
		return "", false, false
	}
	return parameter.Param.Value, quotedDestination, true
}

// fixedOutputCommand accepts commands whose ordinary effects are confined to
// their output stream. The redirect is the only file write in this class.
func fixedOutputCommand(call *syntax.CallExpr, home string) bool {
	if len(call.Args) == 0 {
		return true
	}
	program, fixed := hookpaths.StaticWord(call.Args[0], home)
	if !fixed || strings.ContainsAny(program, "/\\") {
		return false
	}
	switch program {
	case ":", "true", "false", "echo", "printf", "cat", "head", "tail", "wc",
		"grep", "egrep", "fgrep", "du", "stat", "readlink", "realpath", "ls", "dir", "pwd":
		return true
	default:
		return false
	}
}

// knownProjectDestination judges the resolved file, not the spelling of its
// name. A variable expanded without quotes cannot carry a space or glob as
// one destination, so that case is still unresolved.
func knownProjectDestination(value, cwd string, quoted bool, root *os.Root) bool {
	if value == "" || strings.ContainsAny(value, "\x00\r\n") ||
		(!quoted && strings.ContainsAny(value, " \t*?[]")) {
		return false
	}
	relative := value
	if filepath.IsAbs(value) {
		var err error
		relative, err = filepath.Rel(cwd, value)
		if err != nil {
			return false
		}
	}
	if relative == "." || relative == "" {
		return false
	}
	info, err := root.Lstat(relative)
	if err == nil {
		return info.Mode().IsRegular()
	}
	if !errors.Is(err, os.ErrNotExist) {
		return false
	}
	parent, err := root.Stat(filepath.Dir(relative))
	return err == nil && parent.IsDir()
}

// currentProjectSourceOrdinary reads the source anew from the project view.
// Only assignments of the destination to project files are eligible for the
// balanced tier; a source with other actions retains the original finding.
func currentProjectSourceOrdinary(path, cwd, home, name string, quoted bool, root *os.Root) bool {
	before, err := root.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > 16<<10 {
		return false
	}
	file, err := root.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Size() > 16<<10 {
		return false
	}
	content, err := io.ReadAll(io.LimitReader(file, (16<<10)+1))
	if err != nil || len(content) > 16<<10 {
		return false
	}
	source, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(shellparse.Reader(string(content)), "")
	if err != nil || len(source.Stmts) == 0 {
		return false
	}
	for _, stmt := range source.Stmts {
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !plainVariableStatement(stmt) || !ok || len(stmt.Redirs) != 0 ||
			len(call.Args) != 0 || !plainVariableBinding(call, name, cwd, home, quoted, root) {
			return false
		}
	}
	return true
}
