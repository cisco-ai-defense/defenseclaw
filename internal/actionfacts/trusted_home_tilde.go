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
