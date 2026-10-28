// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"path"
	"regexp"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// trustedPOSIXHomeLiteral is an ActiveHome that reads as the same path when
// written unquoted into a POSIX shell word: no whitespace, quoting,
// expansion, glob or tilde characters. A Windows drive home (C:/Users/alice)
// qualifies too, as in posixShellHome (GAP-0912).
var trustedPOSIXHomeLiteral = regexp.MustCompile(`^(?:[A-Za-z]:)?/[A-Za-z0-9._@+/-]*$`)

// trustedPOSIXHomeRewrite has home-anchored operands replaced by ActiveHome.
type trustedPOSIXHomeRewrite struct {
	source string
	// tildeOperands maps each rewritten operand to its original home-path
	// spelling (including HOME parameter forms).
	tildeOperands map[string]string
}

// rewriteTrustedPOSIXHomeTilde replaces home-anchored operands of simple
// commands in a plain pipeline, and "~/..." file redirect
// targets (`echo x >> ~/.ssh/id_ed25519`, GAP-1666) with the trusted
// ActiveHome, the one expansion ActionFacts already resolves from it (see
// projectTrustedPOSIXHomeCatRead).
//
// The shell expands that tilde to $HOME, which ActiveHome is for the
// identity running the action, so the result is exact only while nothing in
// the input can have changed HOME first. The rewrite is therefore limited to
// commands with no assignments or other HOME mentions. Pipeline/list members
// have no redirects or dynamic words; the lone-command redirect handling is
// retained. "~user" forms and command names are never rewritten. The caller
// keeps the rewrite only when its parse is complete.
func rewriteTrustedPOSIXHomeTilde(source, activeHome string) (trustedPOSIXHomeRewrite, bool) {
	if !trustedPOSIXHomeLiteral.MatchString(activeHome) ||
		(!strings.Contains(source, "~") && !strings.Contains(source, "HOME") &&
			!strings.Contains(source, "USER") && !strings.Contains(source, "LOGNAME")) {
		return trustedPOSIXHomeRewrite{}, false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).
		Parse(strings.NewReader(source), "")
	if err != nil || len(file.Stmts) == 0 {
		return trustedPOSIXHomeRewrite{}, false
	}
	binary, isBinary := file.Stmts[0].Cmd.(*syntax.BinaryCmd)
	colonAnd := isBinary && binary.Op == syntax.AndStmt
	var inert []bool
	if len(file.Stmts) != 1 || trustedHomeInertGroup(file.Stmts[0]) || colonAnd {
		var ok bool
		source, inert, ok = normalizeTrustedHomeInertList(file)
		if !ok {
			return trustedPOSIXHomeRewrite{}, false
		}
		file, err = syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(source), "")
		if err != nil || len(file.Stmts) != len(inert) {
			return trustedPOSIXHomeRewrite{}, false
		}
	}
	var words []*syntax.Word
	collectRedirects := func(stmt *syntax.Stmt) bool {
		for _, redirect := range stmt.Redirs {
			switch redirect.Op {
			case syntax.RdrOut, syntax.AppOut, syntax.RdrIn, syntax.RdrClob:
				if literal, ok := firstLiteral(redirect.Word); ok && strings.HasPrefix(literal.Value, "~/") {
					words = append(words, redirect.Word)
				} else if _, anchored := homeAnchoredLiteralWord(redirect.Word); anchored &&
					(plainHomeRewriteWord(redirect.Word) || quotedPlainHomeRewriteWord(redirect.Word)) {
					// bash expands $HOME/${HOME} in a redirect target from
					// the same HOME as ~, as for the arguments (GAP-1773).
					words = append(words, redirect.Word)
				} else if _, user := userHomeRewriteWord(redirect.Word, activeHome); user {
					words = append(words, redirect.Word)
				}
			case syntax.DplOut, syntax.DplIn:
				// A descriptor copy or close (2>&1, >&-) names no file and
				// no home word (GAP-2225).
				if copied := projectPOSIXWord(redirect.Word); copied.Expands ||
					copied.Value != "-" && strings.Trim(copied.Value, "0123456789") != "" {
					return false
				}
			default:
				return false
			}
		}
		return true
	}
	var collect func(*syntax.Stmt, bool) bool
	collect = func(stmt *syntax.Stmt, compound bool) bool {
		if stmt.Negated || stmt.Background || stmt.Coprocess {
			return false
		}
		switch cmd := stmt.Cmd.(type) {
		case *syntax.BinaryCmd:
			if len(stmt.Redirs) != 0 || cmd.Op != syntax.Pipe {
				return false
			}
			return collect(cmd.X, true) && collect(cmd.Y, true)
		case *syntax.CallExpr:
			if len(cmd.Assigns) != 0 || len(cmd.Args) == 0 ||
				(compound && len(stmt.Redirs) != 0) {
				return false
			}
			for _, word := range cmd.Args {
				if _, user := userHomeRewriteWord(word, activeHome); !user && !staticHomeRewriteWord(word) {
					return false
				}
			}
			words = append(words, cmd.Args[1:]...)
			return collectRedirects(stmt)
		case nil:
			// A command-less redirect (`> ~/f`) is the ":" builtin with that
			// redirect (GAP-2076).
			return !compound && len(stmt.Redirs) != 0 && collectRedirects(stmt)
		default:
			return false
		}
	}
	targets := 0
	for index, stmt := range file.Stmts {
		if index < len(inert) && inert[index] {
			continue
		}
		if !collect(stmt, false) {
			return trustedPOSIXHomeRewrite{}, false
		}
		targets++
	}
	if targets != 1 {
		return trustedPOSIXHomeRewrite{}, false
	}
	sort.Slice(words, func(i, j int) bool { return words[i].Pos().Offset() < words[j].Pos().Offset() })
	var out strings.Builder
	last := 0
	rewrite := trustedPOSIXHomeRewrite{tildeOperands: map[string]string{}}
	for _, word := range words {
		if suffix, user := userHomeRewriteWord(word, activeHome); user {
			start, end := int(word.Pos().Offset()), int(word.End().Offset())
			if start < last || end > len(source) {
				return trustedPOSIXHomeRewrite{}, false
			}
			out.WriteString(source[last:start])
			out.WriteString(activeHome + suffix)
			last = end
			rewrite.tildeOperands[activeHome+suffix] = source[start:end]
			continue
		}
		literal, ok := firstLiteral(word)
		if !ok || (literal.Value != "~" && !strings.HasPrefix(literal.Value, "~/")) {
			if suffix, anchored := homeAnchoredLiteralWord(word); anchored &&
				(plainHomeRewriteWord(word) || quotedPlainHomeRewriteWord(word)) {
				start, end := int(word.Pos().Offset()), int(word.End().Offset())
				if start < last || end > len(source) {
					return trustedPOSIXHomeRewrite{}, false
				}
				out.WriteString(source[last:start])
				out.WriteString(activeHome + suffix)
				last = end
				rewrite.tildeOperands[activeHome+suffix] = source[start:end]
			}
			continue
		}
		offset := int(literal.Pos().Offset())
		if offset < last || offset >= len(source) || source[offset] != '~' {
			return trustedPOSIXHomeRewrite{}, false
		}
		out.WriteString(source[last:offset])
		out.WriteString(activeHome)
		last = offset + 1
		// A word that is one plain literal re-parses to exactly home+rest;
		// its path facts get the "~" spelling back.
		if len(word.Parts) == 1 && !strings.ContainsAny(literal.Value, `\*?[`) {
			rewrite.tildeOperands[activeHome+literal.Value[1:]] = literal.Value
		}
	}
	if last == 0 {
		return trustedPOSIXHomeRewrite{}, false
	}
	out.WriteString(source[last:])
	// A separate HOME, USER or LOGNAME mention can change what the rewritten
	// operands name.
	if strings.Contains(out.String(), "HOME") || strings.Contains(out.String(), "USER") ||
		strings.Contains(out.String(), "LOGNAME") {
		return trustedPOSIXHomeRewrite{}, false
	}
	rewrite.source = out.String()
	return rewrite, true
}

// ShellRedirectTargets returns the absolute path of every output redirect
// target the shell opens in command: a literal absolute path, or a home
// spelling (~/..., $HOME/..., ${HOME}/..., "$HOME"/..., <parent>/$USER/...)
// written as the trusted ActiveHome, and on a Windows home also the MSYS
// /c/... spelling of a drive path. The shell expands a redirect target and
// opens it before it runs the command, whatever the program word is or
// expands to, whatever its other words expand to, in any statement shape,
// for every operator that opens the file for writing (>, >>, >|, &>, &>>,
// >& with a file word, <>), and in Bash-only syntax (here-strings, process
// substitution, arrays), so the target names the same file as its absolute
// spelling (GAP-2225, GAP-2268, GAP-2298). The command is read with the
// Bash grammar, which every POSIX command also parses under. A word that
// reads HOME, USER or LOGNAME does not change them; a home spelling is not
// resolved when it follows a statement that names them as written text: an
// assignment of the name, a for/select loop over it, ${HOME:=..},
// arithmetic naming it, a declaration naming it, a variable setter whose
// operand is the name (read HOME, printf -v USER, unset LOGNAME), or eval
// or trap text that parses to one of those. Code that may change them out
// of sight (source ./env.sh, eval "$X", $CMD), a positional word of such
// code (source ./env.sh HOME, $CMD HOME) and text that only reads them
// (eval 'echo $HOME') do not stop the target from being judged as the
// active home (GAP-2328). It returns false when there is no such target, when the command
// does not parse, or when it declares a function. On a Windows home only
// the drive paths below the home are returned (C:/Users/<u>/...): active
// state lives below the home.
func ShellRedirectTargets(command, activeHome string) ([]string, bool) {
	home, ok := normalizeActiveHome(activeHome)
	if !ok || home == "" || !trustedPOSIXHomeLiteral.MatchString(home) {
		return nil, false
	}
	windows := !strings.HasPrefix(home, "/")
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).
		Parse(strings.NewReader(command), "")
	if err != nil || len(file.Stmts) == 0 {
		return nil, false
	}
	type target struct {
		offset int
		path   string
		homed  bool
	}
	var targets []target
	refused := false
	// The home may differ for a home spelling at or after this offset.
	changedAt := -1
	changed := func(offset int) {
		if changedAt < 0 || offset < changedAt {
			changedAt = offset
		}
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		if refused {
			return false
		}
		switch typed := node.(type) {
		case *syntax.FuncDecl:
			refused = true
		case *syntax.ForClause:
			if iter, ok := typed.Loop.(*syntax.WordIter); ok && homeVariableName(iter.Name.Value) {
				changed(int(typed.Pos().Offset()))
			}
		case *syntax.ParamExp:
			if typed.Param != nil && homeVariableName(typed.Param.Value) && typed.Exp != nil &&
				(typed.Exp.Op == syntax.AssignUnset || typed.Exp.Op == syntax.AssignUnsetOrNull) {
				refused = true
			}
		case *syntax.ArithmCmd, *syntax.ArithmExp, *syntax.LetClause:
			start, end := int(typed.Pos().Offset()), int(typed.End().Offset())
			if start < 0 || end > len(command) || start > end || homeNameMention(command[start:end]) {
				refused = true
			}
		case *syntax.Stmt:
			start, end := int(typed.Pos().Offset()), int(typed.End().Offset())
			switch cmd := typed.Cmd.(type) {
			case *syntax.DeclClause:
				for _, assign := range cmd.Args {
					if assign.Name != nil && homeVariableName(assign.Name.Value) {
						changed(start)
					}
				}
				if literalHomeNameMention(cmd) {
					changed(end) // declare -n ref=HOME, declare "HOME$x"
				}
			case *syntax.CallExpr:
				for _, assign := range cmd.Assigns {
					if assign.Name != nil && homeVariableName(assign.Name.Value) {
						changed(start)
					}
				}
				for _, word := range cmd.Args {
					if homeAssignmentWord(projectPOSIXWord(word).Value) {
						changed(start) // env HOME=x make > ~/f
					}
				}
				if len(cmd.Args) == 0 {
					return true
				}
				// Code run from text, a file or an expanded program word may
				// change HOME only out of sight; a later home spelling is
				// still judged as the active home (if HOME did change, the
				// shell writes below another home, which is no benign
				// project write either). Only words that write HOME, USER or
				// LOGNAME keep the skip (GAP-2328).
				if homeVariableWriteCall(cmd, 0) {
					changed(end)
				}
			}
		case *syntax.Redirect:
			if !redirectOpensForWrite(typed) {
				return true
			}
			offset := int(typed.Word.Pos().Offset())
			if !windows {
				if suffix, user := userHomeRewriteWord(typed.Word, home); user {
					targets = append(targets, target{offset, home + suffix, true})
					return true
				}
			}
			if suffix, anchored := homeAnchoredLiteralWord(typed.Word); anchored {
				if (plainHomeRewriteWord(typed.Word) || quotedPlainHomeRewriteWord(typed.Word)) &&
					strings.HasPrefix(suffix, "/") && trustedPOSIXHomeLiteral.MatchString(suffix) {
					targets = append(targets, target{offset, home + suffix, true})
				}
				return true
			}
			if value, ok := staticRedirectPath(typed.Word, windows); ok {
				targets = append(targets, target{offset, value, false})
			}
		}
		return true
	})
	if refused {
		return nil, false
	}
	var paths []string
	for _, item := range targets {
		if item.homed && changedAt >= 0 && item.offset >= changedAt {
			continue
		}
		if windows {
			// Active state lives below the home: a drive path outside it
			// is left out, one below it is spelled with the home's case.
			if _, below := windowsHomeRelative(item.path, home); !below {
				continue
			}
			paths = append(paths, home+item.path[len(home):])
			continue
		}
		paths = append(paths, item.path)
	}
	return paths, len(paths) > 0
}

// windowsHomeRelative returns the part of a drive path below home ("/..."),
// compared without case as the Windows file system does.
func windowsHomeRelative(value, home string) (string, bool) {
	if len(value) <= len(home) || !strings.EqualFold(value[:len(home)], home) || value[len(home)] != '/' {
		return "", false
	}
	rest := value[len(home):]
	return rest, trustedPOSIXHomeLiteral.MatchString(rest)
}

// redirectOpensForWrite reports a redirect that opens its word as a file
// for writing. A >& word that is a descriptor number, "-" or a descriptor
// move (3-) copies or closes a descriptor, as does a >& with a descriptor
// number other than 1 before it.
func redirectOpensForWrite(redirect *syntax.Redirect) bool {
	switch redirect.Op {
	case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.AppClob,
		syntax.RdrAll, syntax.RdrAllClob, syntax.AppAll, syntax.AppAllClob,
		syntax.RdrInOut:
		return true
	case syntax.DplOut:
		if redirect.N != nil && redirect.N.Value != "1" {
			return false
		}
		// A word with a literal / names a file whatever it expands to
		// (>& "$HOME"/f); another expanding word may be a descriptor.
		word := projectPOSIXWord(redirect.Word)
		if word.Expands {
			slash := false
			syntax.Walk(redirect.Word, func(inner syntax.Node) bool {
				switch typed := inner.(type) {
				case *syntax.Lit:
					slash = slash || strings.Contains(typed.Value, "/")
				case *syntax.SglQuoted:
					slash = slash || strings.Contains(typed.Value, "/")
				}
				return true
			})
			return slash
		}
		digits := strings.TrimSuffix(word.Value, "-")
		return word.Value != "-" && strings.Trim(digits, "0123456789") != ""
	}
	return false
}

// staticRedirectPath returns a redirect word that names one absolute path
// with no expansion and no filename pattern. On a Windows home the MSYS
// spelling /c/... is the drive path C:/...
func staticRedirectPath(word *syntax.Word, windows bool) (string, bool) {
	for _, part := range word.Parts {
		switch typed := part.(type) {
		case *syntax.Lit:
			if strings.ContainsAny(typed.Value, "*?[\\~\x00") {
				return "", false
			}
		case *syntax.SglQuoted:
			if typed.Dollar {
				return "", false
			}
		case *syntax.DblQuoted:
			for _, quoted := range typed.Parts {
				if _, literal := quoted.(*syntax.Lit); !literal {
					return "", false
				}
			}
		default:
			return "", false
		}
	}
	projected := projectPOSIXWord(word)
	value := projected.Value
	if projected.Expands || value == "" || strings.ContainsAny(value, "\x00\n") {
		return "", false
	}
	if windows {
		if len(value) >= 3 && value[0] == '/' && isASCIILetter(value[1]) && value[2] == '/' {
			return strings.ToUpper(value[1:2]) + ":" + value[2:], true
		}
		if len(value) >= 3 && isASCIILetter(value[0]) && value[1] == ':' && (value[2] == '/' || value[2] == '\\') {
			return value, true
		}
		return "", false
	}
	return value, strings.HasPrefix(value, "/")
}

func homeVariableName(name string) bool {
	return name == "HOME" || name == "USER" || name == "LOGNAME"
}

func homeNameMention(text string) bool {
	return strings.Contains(text, "HOME") || strings.Contains(text, "USER") ||
		strings.Contains(text, "LOGNAME")
}

var homeNameToken = regexp.MustCompile(`(^|[^A-Za-z0-9_])(HOME|USER|LOGNAME)([^A-Za-z0-9_]|$)`)

// literalHomeNameMention reports text in a declaration that names HOME,
// USER or LOGNAME as a whole word (export HOME, declare -n r=LOGNAME,
// declare "HOME$x"). A read of the variable ($HOME, ${USER}) does not
// write it and does not count; the operand words of an expansion
// (${X:-HOME=/x}) do. USERNAME or HOME_DIR are other names.
func literalHomeNameMention(node syntax.Node) bool {
	found := false
	syntax.Walk(node, func(inner syntax.Node) bool {
		if found {
			return false
		}
		switch typed := inner.(type) {
		case *syntax.ParamExp:
			if typed.Exp != nil && typed.Exp.Word != nil && literalHomeNameMention(typed.Exp.Word) {
				found = true
			}
			if typed.Repl != nil && ((typed.Repl.Orig != nil && literalHomeNameMention(typed.Repl.Orig)) ||
				(typed.Repl.With != nil && literalHomeNameMention(typed.Repl.With))) {
				found = true
			}
			return false
		case *syntax.Lit:
			found = homeNameToken.MatchString(typed.Value)
		case *syntax.SglQuoted:
			found = homeNameToken.MatchString(typed.Value)
		}
		return !found
	})
	return found
}

func homeAssignmentWord(value string) bool {
	return strings.HasPrefix(value, "HOME=") || strings.HasPrefix(value, "USER=") ||
		strings.HasPrefix(value, "LOGNAME=")
}

// homeVariableWriteCall reports a simple command whose written words set
// HOME, USER or LOGNAME: a variable-setting builtin whose operand is the
// name (read HOME, read -a USER, mapfile LOGNAME, getopts o HOME,
// printf -v USER, unset HOME, export/readonly/declare/typeset/local NAME,
// NAME=, NAME+= or a reference to NAME), builtin or command before one of
// those, or eval or trap text that parses to one of them. A positional word
// of other code (source ./env.sh HOME, $CMD HOME, : HOME), an option value
// (read -p HOME) and text that only reads the variable (eval 'echo $HOME')
// set nothing (GAP-2328). A computed name (read "$n") is not the name.
func homeVariableWriteCall(cmd *syntax.CallExpr, depth int) bool {
	if cmd == nil || len(cmd.Args) == 0 || depth > 4 {
		return false
	}
	program := projectPOSIXWord(cmd.Args[0])
	if program.Expands {
		return false
	}
	args := cmd.Args[1:]
	switch program.Value {
	case "builtin", "command":
		return homeVariableWriteCall(&syntax.CallExpr{Args: args}, depth+1)
	case "eval":
		text, ok := staticWordsText(args)
		return ok && homeVariableWriteText(text, depth+1)
	case "trap":
		if len(args) == 0 {
			return false
		}
		text, ok := staticWordsText(args[:1])
		return ok && homeVariableWriteText(text, depth+1)
	case "printf":
		for i := 0; i < len(args); i++ {
			value := projectPOSIXWord(args[i])
			if value.Expands || !strings.HasPrefix(value.Value, "-") || value.Value == "--" {
				return false
			}
			if value.Value == "-v" {
				return i+1 < len(args) && homeOperandWord(args[i+1])
			}
			if name, ok := strings.CutPrefix(value.Value, "-v"); ok {
				return homeVariableName(name)
			}
		}
	case "read":
		return homeOperandAfterOptions(args, "dinNptu")
	case "mapfile", "readarray":
		return homeOperandAfterOptions(args, "dnOsuCc")
	case "getopts", "unset", "export", "readonly", "declare", "typeset", "local":
		return homeOperandAfterOptions(args, "")
	}
	return false
}

// homeOperandAfterOptions reports an operand word, or a name given to -a,
// that names HOME, USER or LOGNAME; the value of an option letter in
// valued (read -p PROMPT) is not a name.
func homeOperandAfterOptions(args []*syntax.Word, valued string) bool {
	for i := 0; i < len(args); i++ {
		value := projectPOSIXWord(args[i])
		if value.Expands {
			continue
		}
		option, isOption := strings.CutPrefix(value.Value, "-")
		if !isOption || option == "" {
			if homeOperandWord(args[i]) {
				return true
			}
			continue
		}
		for j, letter := range option {
			if letter == 'a' || strings.ContainsRune(valued, letter) {
				name := option[j+1:]
				if name == "" && i+1 < len(args) {
					i++
					name = projectPOSIXWord(args[i]).Value
					if projectPOSIXWord(args[i]).Expands {
						name = ""
					}
				}
				if letter == 'a' && homeVariableName(name) {
					return true
				}
				break
			}
		}
	}
	return false
}

// homeOperandWord reports a static word that names HOME, USER or LOGNAME
// as a variable (HOME, HOME=x, HOME+=x, HOME[0]=x) or as the target of a
// reference (r=HOME, as declare -n gives it).
func homeOperandWord(word *syntax.Word) bool {
	value := projectPOSIXWord(word)
	if value.Expands {
		return false
	}
	name, rest, assigned := strings.Cut(value.Value, "=")
	name = strings.TrimSuffix(name, "+")
	if open := strings.IndexByte(name, '['); open >= 0 {
		name = name[:open]
	}
	return homeVariableName(name) || (assigned && homeVariableName(rest))
}

func staticWordsText(words []*syntax.Word) (string, bool) {
	parts := make([]string, 0, len(words))
	for _, word := range words {
		value := projectPOSIXWord(word)
		if value.Expands {
			return "", false
		}
		parts = append(parts, value.Value)
	}
	return strings.Join(parts, " "), true
}

// homeVariableWriteText reports eval or trap text that writes HOME, USER or
// LOGNAME (HOME=/x, export USER=x, read LOGNAME, for HOME in ..., an
// arithmetic or ${HOME:=x} naming it). Text that does not parse runs
// nothing the shell could finish, so it sets nothing.
func homeVariableWriteText(text string, depth int) bool {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(text), "")
	if err != nil {
		return false
	}
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if found {
			return false
		}
		switch typed := node.(type) {
		case *syntax.Assign:
			found = typed.Name != nil && homeVariableName(typed.Name.Value)
		case *syntax.ForClause:
			if iter, ok := typed.Loop.(*syntax.WordIter); ok && homeVariableName(iter.Name.Value) {
				found = true
			}
		case *syntax.DeclClause:
			found = literalHomeNameMention(typed)
		case *syntax.ParamExp:
			found = typed.Param != nil && homeVariableName(typed.Param.Value) && typed.Exp != nil &&
				(typed.Exp.Op == syntax.AssignUnset || typed.Exp.Op == syntax.AssignUnsetOrNull)
		case *syntax.ArithmCmd, *syntax.ArithmExp, *syntax.LetClause:
			start, end := int(typed.Pos().Offset()), int(typed.End().Offset())
			found = start < 0 || end > len(text) || start > end || homeNameMention(text[start:end])
		case *syntax.CallExpr:
			for _, word := range typed.Args {
				if homeAssignmentWord(projectPOSIXWord(word).Value) {
					found = true
				}
			}
			found = found || homeVariableWriteCall(typed, depth)
		}
		return !found
	})
	return found
}

// Only the GAP-0651 shapes count as inert list members: a bare ":" with no
// arguments, optionally with a static ">" or ">>" redirect, which stays in the
// normalized source so its write is still analyzed. "true" and every other
// command keep their own analysis, so "true && ..." stays a conditional flow.
func trustedHomeInertColon(stmt *syntax.Stmt) bool {
	if stmt == nil || stmt.Negated || stmt.Background || stmt.Coprocess || stmt.Disown {
		return false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) != 1 {
		return false
	}
	program := projectPOSIXWord(call.Args[0])
	if program.Expands || program.Value != ":" {
		return false
	}
	for _, redirect := range stmt.Redirs {
		if redirect.Op != syntax.RdrOut && redirect.Op != syntax.AppOut {
			return false
		}
		if target := projectPOSIXWord(redirect.Word); target.Expands {
			return false
		}
	}
	return true
}

func trustedHomeInertGroup(stmt *syntax.Stmt) bool {
	if stmt == nil || len(stmt.Redirs) != 0 || stmt.Negated || stmt.Background || stmt.Coprocess || stmt.Disown {
		return false
	}
	switch group := stmt.Cmd.(type) {
	case *syntax.Block:
		return len(group.Stmts) == 1 && trustedHomeInertColon(group.Stmts[0]) && len(group.Stmts[0].Redirs) == 0
	case *syntax.Subshell:
		return len(group.Stmts) == 1 && trustedHomeInertColon(group.Stmts[0]) && len(group.Stmts[0].Redirs) == 0
	default:
		return false
	}
}

// A colon succeeds unconditionally, so a colon AND target executes exactly
// like a list. Braces and subshells containing only a colon have no state to
// carry into the target command. Keep every other construct out of this proof.
// Inert members are written as "true" (a known no-op command for the parse);
// the returned mask marks them, one entry per statement of the result.
func normalizeTrustedHomeInertList(file *syntax.File) (string, []bool, bool) {
	var parts []string
	var inert []bool
	targets := 0
	printStmt := func(stmt *syntax.Stmt) (string, bool) {
		var buf bytes.Buffer
		if err := syntax.NewPrinter().Print(&buf, stmt); err != nil {
			return "", false
		}
		return buf.String(), true
	}
	for _, stmt := range file.Stmts {
		if trustedHomeInertGroup(stmt) {
			parts, inert = append(parts, "true"), append(inert, true)
			continue
		}
		if binary, ok := stmt.Cmd.(*syntax.BinaryCmd); ok &&
			binary.Op == syntax.AndStmt && len(stmt.Redirs) == 0 &&
			trustedHomeInertColon(binary.X) && len(binary.X.Redirs) == 0 {
			stmt = binary.Y
			parts, inert = append(parts, "true"), append(inert, true)
		}
		colon := trustedHomeInertColon(stmt)
		if !colon {
			if _, ok := stmt.Cmd.(*syntax.CallExpr); !ok ||
				stmt.Negated || stmt.Background || stmt.Coprocess || stmt.Disown {
				return "", nil, false
			}
			targets++
		}
		segment, ok := printStmt(stmt)
		if !ok || strings.Contains(segment, "\n") {
			return "", nil, false
		}
		if colon {
			if !strings.HasPrefix(segment, ":") {
				return "", nil, false
			}
			segment = "true" + segment[1:]
		}
		parts, inert = append(parts, segment), append(inert, colon)
	}
	if targets != 1 {
		return "", nil, false
	}
	source := strings.Join(parts, "; ")
	// The mask must line up with the statements the result parses into.
	reparsed, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(source), "")
	if err != nil || len(reparsed.Stmts) != len(inert) {
		return "", nil, false
	}
	return source, inert, true
}

func normalizeTrustedHomeInertListSource(source string) (string, []bool, bool) {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(source), "")
	if err != nil || file == nil || len(file.Stmts) == 0 {
		return "", nil, false
	}
	return normalizeTrustedHomeInertList(file)
}

func staticHomeRewriteWord(word *syntax.Word) bool {
	if plainHomeRewriteWord(word) {
		return true
	}
	for _, part := range word.Parts {
		switch part.(type) {
		case *syntax.Lit, *syntax.SglQuoted, *syntax.DblQuoted:
		default:
			return false
		}
	}
	return true
}

func plainHomeRewriteWord(word *syntax.Word) bool {
	if _, ok := homeAnchoredLiteralWord(word); !ok {
		return false
	}
	for _, part := range word.Parts {
		switch part.(type) {
		case *syntax.Lit, *syntax.ParamExp:
		default:
			return false
		}
	}
	return true
}

// quotedPlainHomeRewriteWord reports a home word that starts with a
// double-quoted "$HOME" or "${HOME}" ("$HOME/...", "$HOME"/..., and
// "$HOME"'/...' with literal or single-quoted parts after it) whose path
// needs no quoting, so the unquoted ActiveHome spelling of the rewrite
// names exactly the same path: the shell removes the quotes (GAP-1773).
func quotedPlainHomeRewriteWord(word *syntax.Word) bool {
	if word == nil || len(word.Parts) == 0 {
		return false
	}
	if _, quoted := word.Parts[0].(*syntax.DblQuoted); !quoted {
		return false
	}
	for _, part := range word.Parts[1:] {
		switch typed := part.(type) {
		case *syntax.Lit, *syntax.SglQuoted:
		case *syntax.DblQuoted:
			// "$HOME"/.defenseclaw/"config.yaml": literal text only.
			for _, quoted := range typed.Parts {
				if _, literal := quoted.(*syntax.Lit); !literal {
					return false
				}
			}
		default:
			return false
		}
	}
	suffix, anchored := homeAnchoredLiteralWord(word)
	return anchored && trustedPOSIXHomeLiteral.MatchString(suffix)
}

// userHomeRewriteWord reports a word that names a path below the home
// through the user name, /home/$USER/... or "/Users/${LOGNAME}/..." (quoted
// or not), when the literal parent directory plus the ActiveHome base name
// is ActiveHome, and returns that path below the home. bash expands $USER
// from the same login as HOME; when the two disagree the word names another
// user's home, so reading it as ActiveHome errs only toward a write fact of
// the active home, never away from one (GAP-2269).
func userHomeRewriteWord(word *syntax.Word, activeHome string) (string, bool) {
	if word == nil || len(word.Parts) == 0 || !strings.HasPrefix(activeHome, "/") {
		return "", false
	}
	var prefix, suffix strings.Builder
	params := 0
	text := func(value string) {
		if params == 0 {
			prefix.WriteString(value)
		} else {
			suffix.WriteString(value)
		}
	}
	param := func(part syntax.WordPart) bool {
		if !plainNamedParameter(part, "USER") && !plainNamedParameter(part, "LOGNAME") {
			return false
		}
		params++
		return true
	}
	for _, part := range word.Parts {
		switch typed := part.(type) {
		case *syntax.Lit:
			text(typed.Value)
		case *syntax.SglQuoted:
			if typed.Dollar {
				return "", false
			}
			text(typed.Value)
		case *syntax.ParamExp:
			if !param(typed) {
				return "", false
			}
		case *syntax.DblQuoted:
			if typed.Dollar {
				return "", false
			}
			for _, quoted := range typed.Parts {
				switch value := quoted.(type) {
				case *syntax.Lit:
					text(value.Value)
				case *syntax.ParamExp:
					if !param(value) {
						return "", false
					}
				default:
					return "", false
				}
			}
		default:
			return "", false
		}
	}
	parent, below := prefix.String(), suffix.String()
	if params != 1 || !strings.HasSuffix(parent, "/") || parent+path.Base(activeHome) != activeHome ||
		!trustedPOSIXHomeLiteral.MatchString(parent) || !strings.HasPrefix(below, "/") || below == "/" ||
		!trustedPOSIXHomeLiteral.MatchString(below) {
		return "", false
	}
	return below, true
}

func firstLiteral(word *syntax.Word) (*syntax.Lit, bool) {
	if word == nil || len(word.Parts) == 0 {
		return nil, false
	}
	literal, ok := word.Parts[0].(*syntax.Lit)
	return literal, ok
}

// respellTrustedPOSIXHomeTilde gives the path facts of rewritten operands
// back their "~" spelling (Value and Normalized), as a partial parse of the
// original text records them, while Resolved keeps the ActiveHome path, so
// rules that match a home path by its spelling keep matching it. A static
// redirect target of those commands gets the same spelling, so it still
// names its path fact: the owners that tie a redirect to the path it writes
// compare the two values, and without it a lone `echo k >> ~/.ssh/
// authorized_keys` lost its finding while the absolute and chained forms
// kept theirs (GAP-0892, GAP-0894, GAP-0896).
func respellTrustedPOSIXHomeTilde(facts *Facts, commandIDs map[int64]struct{}, tildeOperands map[string]string) {
	if facts == nil || len(tildeOperands) == 0 {
		return
	}
	for index := range facts.Commands {
		command := &facts.Commands[index]
		if _, ok := commandIDs[command.ID]; !ok || command.Dialect != DialectPOSIX {
			continue
		}
		for redirectIndex := range command.Redirects {
			redirect := &command.Redirects[redirectIndex]
			if spelling, ok := tildeOperands[redirect.Target]; ok && !redirect.Expands {
				redirect.Target = spelling
			}
		}
	}
	for index := range facts.Paths {
		path := &facts.Paths[index]
		if _, ok := commandIDs[path.CommandID]; !ok || path.Flavor != PathFlavorPOSIX {
			continue
		}
		spelling, ok := tildeOperands[path.Value]
		if !ok || path.Resolved != path.Value {
			continue
		}
		path.Value = spelling
		path.Normalized = spelling
		path.Absolute = false
	}
}
