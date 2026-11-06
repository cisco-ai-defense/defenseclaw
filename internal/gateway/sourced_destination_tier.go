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
	if !known || !unresolvedVariableRedirectForm(command, cwd, facts.ActiveHome,
		request.targetMemo.ProtectedAuthorizedKeysPaths(facts.ActiveHome), root) {
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
func unresolvedVariableRedirectForm(command, cwd, home string, protectedPaths []string, root *os.Root) bool {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(shellparse.Reader(command), "")
	if err != nil || len(file.Stmts) < 2 {
		return false
	}
	name, quoted, ok := variableRedirectWriter(file.Stmts[len(file.Stmts)-1], home)
	if !ok {
		return false
	}
	proof := sourcedDestinationProof{name: name, cwd: cwd, home: home,
		quoted: quoted, protectedPaths: protectedPaths, root: root}
	return proof.statements(file.Stmts[:len(file.Stmts)-1], false, 0) && proof.bound && proof.sourced
}

// sourcedDestinationProof visits each possible assignment before the final
// redirect. An unsupported statement leaves the conservative verdict intact.
type sourcedDestinationProof struct {
	name, cwd, home string
	quoted          bool
	protectedPaths  []string
	root            *os.Root
	bound, sourced  bool
}

func (p *sourcedDestinationProof) statements(stmts []*syntax.Stmt, inSource bool, depth int) bool {
	if depth > 8 || len(stmts) > 32 {
		return false
	}
	for _, stmt := range stmts {
		if !p.statement(stmt, inSource, depth) {
			return false
		}
	}
	return true
}

func (p *sourcedDestinationProof) statement(stmt *syntax.Stmt, inSource bool, depth int) bool {
	if !plainVariableStatement(stmt) || len(stmt.Redirs) != 0 {
		return false
	}
	switch call := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		if len(call.Args) == 0 || len(call.Args) != 0 && call.Args[0].Lit() == "export" {
			if !p.variableBinding(call) {
				return false
			}
			p.bound = true
			return true
		}
		if len(call.Assigns) != 0 {
			return false
		}
		switch call.Args[0].Lit() {
		case ".", "source":
			if inSource || len(call.Args) != 2 {
				return false
			}
			path, fixed := hookpaths.StaticWord(call.Args[1], p.home)
			// A bare source name can be found through the shell's PATH rather
			// than at the event cwd, which is the only source view available here.
			if !fixed || !strings.Contains(path, "/") ||
				!knownProjectDestination(path, p.cwd, true, p.protectedPaths, p.root) ||
				!p.currentProjectSourceOrdinary(path, depth+1) {
				return false
			}
			p.sourced = true
			return true
		case ":":
			return len(call.Args) == 1
		default:
			return false
		}
	case *syntax.IfClause:
		return p.ifClause(call, inSource, depth+1)
	default:
		return false
	}
}

func (p *sourcedDestinationProof) ifClause(clause *syntax.IfClause, inSource bool, depth int) bool {
	if depth > 8 || !ordinarySourceCondition(clause.Cond) {
		return false
	}
	thenProof, elseProof := *p, *p
	if !thenProof.statements(clause.Then, inSource, depth) {
		return false
	}
	if clause.Else != nil {
		if len(clause.Else.Cond) == 0 {
			if !elseProof.statements(clause.Else.Then, inSource, depth) {
				return false
			}
		} else if !elseProof.ifClause(clause.Else, inSource, depth+1) {
			return false
		}
	}
	p.bound = thenProof.bound && elseProof.bound
	p.sourced = thenProof.sourced || elseProof.sourced
	return true
}

func ordinarySourceCondition(stmts []*syntax.Stmt) bool {
	if len(stmts) != 1 || !plainVariableStatement(stmts[0]) || len(stmts[0].Redirs) != 0 {
		return false
	}
	call, ok := stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) == 0 {
		return false
	}
	switch call.Args[0].Lit() {
	case "test", "[", "true", "false", ":":
	default:
		return false
	}
	for _, arg := range call.Args[1:] {
		if !ordinaryConditionWord(arg) {
			return false
		}
	}
	return true
}

func ordinaryConditionWord(word *syntax.Word) bool {
	if word == nil {
		return false
	}
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit, *syntax.SglQuoted:
		case *syntax.DblQuoted:
			if part.Dollar || !ordinaryConditionWord(&syntax.Word{Parts: part.Parts}) {
				return false
			}
		case *syntax.ParamExp:
			if part.Param == nil || part.Excl || part.Length || part.Width || part.IsSet ||
				part.Index != nil || part.Slice != nil || part.Exp != nil || part.Repl != nil {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func plainVariableStatement(stmt *syntax.Stmt) bool {
	return stmt != nil && stmt.Cmd != nil && !stmt.Background &&
		!stmt.Coprocess && !stmt.Disown && !stmt.Negated
}

func (p *sourcedDestinationProof) variableBinding(call *syntax.CallExpr) bool {
	if len(call.Args) != 0 {
		if call.Args[0].Lit() != "export" {
			return false
		}
		if len(call.Assigns) == 0 && len(call.Args) == 2 {
			value, fixed := hookpaths.StaticWord(call.Args[1], p.home)
			prefix := p.name + "="
			if !fixed || !strings.HasPrefix(value, prefix) {
				return false
			}
			assigned := strings.TrimPrefix(value, prefix)
			// Bash performs tilde expansion in an export assignment, including
			// after a colon. A plain static word alone does not establish its path.
			return !strings.HasPrefix(assigned, "~") && !strings.Contains(assigned, ":~") &&
				knownProjectDestination(assigned, p.cwd, p.quoted, p.protectedPaths, p.root)
		}
		if len(call.Args) != 1 {
			return false
		}
	}
	if len(call.Assigns) != 1 {
		return false
	}
	a := call.Assigns[0]
	if a.Name == nil || a.Name.Value != p.name || a.Value == nil ||
		a.Append || a.Array != nil || a.Index != nil {
		return false
	}
	value, fixed := hookpaths.StaticWord(a.Value, p.home)
	return fixed && knownProjectDestination(value, p.cwd, p.quoted, p.protectedPaths, p.root)
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
func knownProjectDestination(value, cwd string, quoted bool, protectedPaths []string, root *os.Root) bool {
	if value == "" || strings.ContainsAny(value, "\x00\r\n") ||
		(!quoted && strings.ContainsAny(value, " \t*?[]")) {
		return false
	}
	relative, err := projectRelative(value, cwd)
	if err != nil {
		return false
	}
	if relative == "." || relative == "" {
		return false
	}
	info, err := root.Lstat(relative)
	if err == nil {
		if !info.Mode().IsRegular() {
			return false
		}
		for _, path := range protectedPaths {
			if protected, err := os.Stat(path); err == nil && os.SameFile(info, protected) {
				return false
			}
		}
		return true
	}
	if !errors.Is(err, os.ErrNotExist) {
		return false
	}
	parent, err := root.Stat(filepath.Dir(relative))
	return err == nil && parent.IsDir()
}

func projectRelative(path, cwd string) (string, error) {
	relative := path
	if filepath.IsAbs(path) {
		var err error
		relative, err = filepath.Rel(cwd, path)
		if err != nil {
			return "", err
		}
	}
	clean := filepath.Clean(relative)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", os.ErrPermission
	}
	return relative, nil
}

// currentProjectSourceOrdinary reads the source anew from the project view.
// Only assignments of the destination to project files are eligible for the
// balanced tier; a source with other actions retains the original finding.
func (p *sourcedDestinationProof) currentProjectSourceOrdinary(path string, depth int) bool {
	relative, err := projectRelative(path, p.cwd)
	if err != nil {
		return false
	}
	before, err := p.root.Lstat(relative)
	if err != nil || !before.Mode().IsRegular() || before.Size() > 16<<10 {
		return false
	}
	file, err := p.root.Open(relative)
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
	return p.statements(source.Stmts, true, depth)
}
