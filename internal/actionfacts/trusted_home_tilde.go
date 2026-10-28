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
	// homeGlobs is set when a $HOME or ${HOME} pattern was rewritten.
	homeGlobs bool
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
		(!strings.Contains(source, "~") && !strings.Contains(source, "HOME")) {
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
	// scripts holds the rewritten -c script of a shell that a find -exec
	// or an xargs runs (GAP-2304).
	scripts := map[*syntax.Word]string{}
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
				if !staticHomeRewriteWord(word) {
					return false
				}
			}
			words = append(words, cmd.Args[1:]...)
			for word, script := range embeddedShellScriptHomeRewrites(cmd.Args, activeHome) {
				scripts[word] = script
			}
			for _, redirect := range stmt.Redirs {
				switch redirect.Op {
				case syntax.RdrOut, syntax.AppOut, syntax.RdrIn, syntax.ClbOut:
					if literal, ok := firstLiteral(redirect.Word); ok && strings.HasPrefix(literal.Value, "~/") {
						words = append(words, redirect.Word)
					}
				default:
					return false
				}
			}
			return true
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
		if script, ok := scripts[word]; ok {
			start, end := int(word.Pos().Offset()), int(word.End().Offset())
			if start < last || end > len(source) {
				return trustedPOSIXHomeRewrite{}, false
			}
			out.WriteString(source[last:start])
			out.WriteString("'" + script + "'")
			last = end
			continue
		}
		if prefix, ok := findOptionHomeWord(word); ok {
			// `-f$HOME/...`: the -f path of BSD find, attached (GAP-2135).
			suffix, _ := homeAnchoredLiteralWord(&syntax.Word{Parts: word.Parts[1:]})
			start, end := int(word.Pos().Offset()), int(word.End().Offset())
			if start < last || end > len(source) {
				return trustedPOSIXHomeRewrite{}, false
			}
			out.WriteString(source[last:start])
			out.WriteString(prefix + activeHome + suffix)
			last = end
			continue
		}
		if suffix, ok := bareHomeWord(word); ok {
			// `find $HOME -type f -delete`, `"$HOME"/`: the home itself, as
			// a lone ~ is (GAP-2267).
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
		if suffix, ok := homeGlobRewriteWord(word); ok {
			// `rm -rf $HOME/.defenseclaw/*`: the shell expands HOME and
			// then the pattern, as for ~/ (GAP-2047).
			start, end := int(word.Pos().Offset()), int(word.End().Offset())
			if start < last || end > len(source) {
				return trustedPOSIXHomeRewrite{}, false
			}
			out.WriteString(source[last:start])
			out.WriteString(activeHome + suffix)
			last = end
			rewrite.homeGlobs = true
			continue
		}
		literal, ok := firstLiteral(word)
		if !ok || (literal.Value != "~" && !strings.HasPrefix(literal.Value, "~/")) {
			if suffix, anchored := homeAnchoredLiteralWord(word); anchored &&
				plainHomeRewriteWord(word) {
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
	// A separate HOME mention can change what the rewritten operands name.
	if strings.Contains(out.String(), "HOME") {
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
	if _, ok := bareHomeWord(word); ok {
		return true
	}
	if _, ok := findOptionHomeWord(word); ok {
		return true
	}
	if _, ok := homeGlobRewriteWord(word); ok {
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

// findOptionHomeWord reports a find option word whose -f path is attached
// and starts with a plain $HOME or ${HOME} (`-f$HOME/.x`, `-xf${HOME}/.x`)
// and returns its option letters; the shell expands that HOME as in a
// separate word (GAP-2135).
func findOptionHomeWord(word *syntax.Word) (string, bool) {
	literal, ok := firstLiteral(word)
	if !ok || len(word.Parts) < 2 || !findAttachedPathOption.MatchString(literal.Value) {
		return "", false
	}
	rest := &syntax.Word{Parts: word.Parts[1:]}
	if _, anchored := homeAnchoredLiteralWord(rest); !anchored || !plainHomeRewriteWord(rest) {
		return "", false
	}
	if _, home := word.Parts[1].(*syntax.ParamExp); !home {
		return "", false
	}
	return literal.Value, true
}

var findAttachedPathOption = regexp.MustCompile(`^-[EHLPXdsx]*f$`)

// bareHomeWord reports a word that is the home directory itself through a
// plain HOME parameter: $HOME, ${HOME}, "$HOME", "${HOME}", each optionally
// followed by one "/" inside or outside the quotes. It returns that "/" or
// "". homeAnchoredLiteralWord needs a path below the home, so these words
// were never rewritten and a find from $HOME was not judged as one from ~
// (GAP-2267).
func bareHomeWord(word *syntax.Word) (string, bool) {
	if word == nil || len(word.Parts) == 0 || len(word.Parts) > 2 {
		return "", false
	}
	slash := func(part syntax.WordPart) bool {
		literal, ok := part.(*syntax.Lit)
		return ok && literal.Value == "/"
	}
	suffix := ""
	if len(word.Parts) == 2 {
		if !slash(word.Parts[1]) {
			return "", false
		}
		suffix = "/"
	}
	switch first := word.Parts[0].(type) {
	case *syntax.ParamExp:
		if !plainHomeParameter(first) {
			return "", false
		}
	case *syntax.DblQuoted:
		if first.Dollar || len(first.Parts) == 0 || len(first.Parts) > 2 ||
			!plainHomeParameter(first.Parts[0]) {
			return "", false
		}
		if len(first.Parts) == 2 {
			if suffix != "" || !slash(first.Parts[1]) {
				return "", false
			}
			suffix = "/"
		}
	default:
		return "", false
	}
	return suffix, true
}

// plainHomeRewriteWord reports a home-anchored word the rewrite writes back
// unquoted as ActiveHome plus its path. A quoted part ("$HOME/.x/y",
// "$HOME"/.x) reads the same unquoted only when the path holds no blank,
// pattern or other shell character, so only such a path is taken
// (GAP-2047).
func plainHomeRewriteWord(word *syntax.Word) bool {
	suffix, ok := homeAnchoredLiteralWord(word)
	if !ok {
		return false
	}
	quoted := false
	for _, part := range word.Parts {
		switch part.(type) {
		case *syntax.Lit, *syntax.ParamExp:
		case *syntax.DblQuoted, *syntax.SglQuoted:
			quoted = true
		default:
			return false
		}
	}
	return !quoted || trustedPOSIXHomeLiteral.MatchString(suffix)
}

// homeGlobRewriteWord reports an unquoted $HOME or ${HOME} followed by
// plain literal text that holds a pathname pattern (`$HOME/.defenseclaw/*`)
// and returns that text. The shell expands HOME first and then the
// pattern, so ActiveHome plus the same text names the same files.
func homeGlobRewriteWord(word *syntax.Word) (string, bool) {
	if word == nil || len(word.Parts) < 2 {
		return "", false
	}
	var suffix strings.Builder
	switch first := word.Parts[0].(type) {
	case *syntax.ParamExp:
		if !plainHomeParameter(first) {
			return "", false
		}
	case *syntax.DblQuoted:
		// `"$HOME/.defenseclaw/"*`, `"$HOME"/.defenseclaw/*`: HOME and
		// plain path text inside the quotes read the same unquoted, and
		// the pattern stays outside them (pod check17 row c).
		if first.Dollar || len(first.Parts) == 0 || len(first.Parts) > 2 ||
			!plainHomeParameter(first.Parts[0]) {
			return "", false
		}
		if len(first.Parts) == 2 {
			literal, ok := first.Parts[1].(*syntax.Lit)
			if !ok || !trustedPOSIXHomeLiteral.MatchString(literal.Value) {
				return "", false
			}
			suffix.WriteString(literal.Value)
		}
	default:
		return "", false
	}
	for _, part := range word.Parts[1:] {
		literal, ok := part.(*syntax.Lit)
		if !ok {
			return "", false
		}
		suffix.WriteString(literal.Value)
	}
	text := suffix.String()
	if !strings.HasPrefix(text, "/") || !strings.ContainsAny(text, "*?[") ||
		strings.ContainsAny(text, "\\~\x00$`") {
		return "", false
	}
	return text, true
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

// embeddedShellScriptHomeRewrites rewrites the single-quoted -c script of a
// POSIX shell that a find -exec/-execdir/-ok/-okdir or an xargs runs
// (`find /tmp -maxdepth 0 -exec sh -c 'rm -rf ~/.defenseclaw/hooks' \;`).
// That shell expands its own "~" to the HOME it inherits, which the outer
// rewrite proves unchanged, so the script gets the same rewrite as a
// top-level command (GAP-2304). A script that does not rewrite, or whose
// rewrite holds a single quote, is left as it is.
func embeddedShellScriptHomeRewrites(args []*syntax.Word, activeHome string) map[*syntax.Word]string {
	if len(args) < 4 {
		return nil
	}
	program, ok := firstLiteral(args[0])
	if !ok || len(args[0].Parts) != 1 {
		return nil
	}
	switch path.Base(program.Value) {
	case "find", "xargs":
	default:
		return nil
	}
	var rewrites map[*syntax.Word]string
	for index := 3; index < len(args); index++ {
		option, optionOK := firstLiteral(args[index-1])
		shell, shellOK := firstLiteral(args[index-2])
		if !optionOK || !shellOK || len(args[index-1].Parts) != 1 || len(args[index-2].Parts) != 1 ||
			option.Value != "-c" {
			continue
		}
		switch path.Base(shell.Value) {
		case "sh", "bash", "dash", "ksh", "mksh", "ash":
		default:
			continue
		}
		if len(args[index].Parts) != 1 {
			continue
		}
		quoted, isQuoted := args[index].Parts[0].(*syntax.SglQuoted)
		if !isQuoted || quoted.Dollar || !strings.Contains(quoted.Value, "~") {
			continue
		}
		rewrite, rewritten := rewriteTrustedPOSIXHomeTilde(quoted.Value, activeHome)
		if !rewritten || strings.Contains(rewrite.source, "'") {
			continue
		}
		if rewrites == nil {
			rewrites = map[*syntax.Word]string{}
		}
		rewrites[args[index]] = rewrite.source
	}
	return rewrites
}
