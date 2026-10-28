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
				if _, user := userHomeRewriteWord(word, activeHome); !user && !staticHomeRewriteWord(word) {
					if _, option := optionHomeRewriteWord(word); !option {
						if _, ok := quotedOptionHomeRewrite(word, activeHome); !ok {
							return false
						}
					}
				}
			}
			words = append(words, cmd.Args[1:]...)
			for word, script := range embeddedShellScriptHomeRewrites(cmd.Args, activeHome) {
				scripts[word] = script
			}
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
		if rest, option := optionHomeRewriteWord(word); option {
			// dd of=$HOME/f: only the home word after the key is respelled.
			suffix, _ := homeAnchoredLiteralWord(rest)
			start, end := int(rest.Pos().Offset()), int(rest.End().Offset())
			if start < last || end > len(source) {
				return trustedPOSIXHomeRewrite{}, false
			}
			out.WriteString(source[last:start])
			out.WriteString(activeHome + suffix)
			last = end
			rewrite.tildeOperands[activeHome+suffix] = source[start:end]
			continue
		}
		if respelled, ok := quotedOptionHomeRewrite(word, activeHome); ok {
			// "of=$HOME/f", 'of='$HOME/f: the whole word is respelled.
			start, end := int(word.Pos().Offset()), int(word.End().Offset())
			if start < last || end > len(source) {
				return trustedPOSIXHomeRewrite{}, false
			}
			out.WriteString(source[last:start])
			out.WriteString(respelled.key + respelled.path)
			last = end
			rewrite.tildeOperands[respelled.path] = "$HOME" + respelled.suffix
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
// Bash grammar, which every POSIX command also parses under.
//
// A home spelling is left unresolved only after a statement that sets
// HOME, USER or LOGNAME to another literal value in the shell that opens
// the target (homeValueSetBy, GAP-2328). Everything else leaves it judged
// as the active home: a word that reads the name, the name as a positional
// word or option value, code that may change it out of sight (source, .,
// eval "$X", $CMD), a value the shell computes or reads (read, mapfile,
// printf -v, getopts, $(...)), unset (bash then expands ~ to the passwd
// home), a prefix assignment (HOME=/x make > ~/f: the shell opens ~/f
// before it assigns), and a statement in a subshell, pipeline, background
// job or a branch that may not run. If HOME did change, the shell writes
// below another home, which is no benign project write either, and only an
// active state target can change a verdict. It returns false when there is
// no such target, when the command does not parse, or when it declares a
// function. On a Windows home only the drive paths below the home are
// returned (C:/Users/<u>/...): active state lives below the home.
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
		names  homeNames // the names the spelling expands
	}
	var targets []target
	refused := false
	// The name may differ for a spelling that expands it at or after
	// this offset.
	changedAt := map[homeNames]int{}
	changed := func(name homeNames, offset int) {
		if at, ok := changedAt[name]; !ok || offset < at {
			changedAt[name] = offset
		}
	}
	for _, stmt := range currentShellStmts(file.Stmts) {
		set := homeValueSetBy(stmt, home, windows, 0)
		for _, bit := range []homeNames{1, 2, 4} {
			if set&bit != 0 {
				changed(bit, int(stmt.End().Offset()))
			}
		}
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		if refused {
			return false
		}
		switch typed := node.(type) {
		case *syntax.FuncDecl:
			refused = true
		case *syntax.Redirect:
			if !redirectOpensForWrite(typed) {
				return true
			}
			offset := int(typed.Word.Pos().Offset())
			if !windows {
				if suffix, user := userHomeRewriteWord(typed.Word, home); user {
					targets = append(targets, target{offset, home + suffix, wordHomeNames(typed.Word)})
					return true
				}
			}
			if suffix, anchored := homeAnchoredLiteralWord(typed.Word); anchored {
				if (plainHomeRewriteWord(typed.Word) || quotedPlainHomeRewriteWord(typed.Word)) &&
					strings.HasPrefix(suffix, "/") && trustedPOSIXHomeLiteral.MatchString(suffix) {
					targets = append(targets, target{offset, home + suffix, homeNameBit("HOME")})
				}
				return true
			}
			if value, ok := staticRedirectPath(typed.Word, windows); ok {
				targets = append(targets, target{offset, value, 0})
			}
		}
		return true
	})
	if refused {
		return nil, false
	}
	var paths []string
	for _, item := range targets {
		stale := false
		for name, at := range changedAt {
			stale = stale || (item.names&name != 0 && item.offset >= at)
		}
		if stale {
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

// currentShellStmts returns the statements of list that the shell runs in
// its own process whenever the list runs, in order: the members of a { }
// group and the left side of && or ||. A background job, a coprocess, a
// pipeline part and a subshell run in another process; the right side of
// && or || and an if, while, until or case body may not run; so a
// variable such a statement sets is not known to be set afterwards.
func currentShellStmts(list []*syntax.Stmt) []*syntax.Stmt {
	var out []*syntax.Stmt
	var add func(*syntax.Stmt)
	add = func(stmt *syntax.Stmt) {
		if stmt == nil || stmt.Background || stmt.Coprocess {
			return
		}
		switch cmd := stmt.Cmd.(type) {
		case *syntax.Block:
			for _, inner := range cmd.Stmts {
				add(inner)
			}
		case *syntax.BinaryCmd:
			if cmd.Op == syntax.AndStmt || cmd.Op == syntax.OrStmt {
				add(cmd.X)
			}
		default:
			out = append(out, stmt)
		}
	}
	for _, stmt := range list {
		add(stmt)
	}
	return out
}

// homeNames is a set of the names HOME, USER and LOGNAME.
type homeNames uint8

func homeNameBit(name string) homeNames {
	switch name {
	case "HOME":
		return 1
	case "USER":
		return 2
	case "LOGNAME":
		return 4
	}
	return 0
}

// homeValueSetBy returns the names among HOME, USER and LOGNAME that a
// statement sets to a literal value other than the active one: a bare
// assignment (HOME=/tmp/h, HOME+=x), export, readonly, declare or typeset
// of NAME=value (no option or only -x, -r, -g; builtin or command before
// it), a for loop over the name with literal words, arithmetic that
// assigns the name (a number, never a home), or eval text or DEBUG trap
// text whose current-shell statements do one of those. A value the shell
// computes or reads (read, mapfile, printf -v, getopts, $(...)), unset, a
// reference (declare -n) and a prefix assignment of another command set no
// such value (GAP-2328).
func homeValueSetBy(stmt *syntax.Stmt, home string, windows bool, depth int) homeNames {
	if stmt == nil || depth > 4 {
		return 0
	}
	var set homeNames
	switch cmd := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		if len(cmd.Args) > 0 {
			return homeValueSetByCall(cmd.Args, home, windows, depth)
		}
		for _, assign := range cmd.Assigns {
			set |= literalHomeAssign(assign, home, windows)
		}
	case *syntax.DeclClause:
		switch cmd.Variant.Value {
		case "export", "readonly", "declare", "typeset":
		default:
			return 0
		}
		for _, assign := range cmd.Args {
			if assign.Name == nil {
				if assign.Value == nil || !homeDeclOption(projectPOSIXWord(assign.Value)) {
					return 0
				}
				continue
			}
			set |= literalHomeAssign(assign, home, windows)
		}
	case *syntax.ForClause:
		iter, ok := cmd.Loop.(*syntax.WordIter)
		if !ok || homeNameBit(iter.Name.Value) == 0 || len(iter.Items) == 0 {
			return 0
		}
		last := ""
		for _, item := range iter.Items {
			value := projectPOSIXWord(item)
			if value.Expands {
				return 0
			}
			last = value.Value
		}
		if homeValueDiffers(iter.Name.Value, last, home, windows) {
			set = homeNameBit(iter.Name.Value)
		}
	case *syntax.ArithmCmd:
		set = arithmAssignedHomeNames(cmd.X)
	case *syntax.LetClause:
		for _, expr := range cmd.Exprs {
			set |= arithmAssignedHomeNames(expr)
		}
	}
	return set
}

// homeValueSetByCall is homeValueSetBy for a simple command given its
// words.
func homeValueSetByCall(args []*syntax.Word, home string, windows bool, depth int) homeNames {
	if len(args) == 0 || depth > 4 {
		return 0
	}
	program := projectPOSIXWord(args[0])
	if program.Expands {
		return 0
	}
	rest := args[1:]
	switch program.Value {
	case "builtin", "command":
		return homeValueSetByCall(rest, home, windows, depth+1)
	case "export", "readonly", "declare", "typeset":
		var set homeNames
		for _, word := range rest {
			value := projectPOSIXWord(word)
			if value.Expands {
				return 0
			}
			if strings.HasPrefix(value.Value, "-") || strings.HasPrefix(value.Value, "+") {
				if !homeDeclOption(value) {
					return 0
				}
				continue
			}
			name, assigned, ok := strings.Cut(value.Value, "=")
			if !ok {
				continue
			}
			appended := strings.HasSuffix(name, "+")
			name = strings.TrimSuffix(name, "+")
			if homeNameBit(name) != 0 && ((appended && assigned != "") ||
				(!appended && homeValueDiffers(name, assigned, home, windows))) {
				set |= homeNameBit(name)
			}
		}
		return set
	case "eval":
		text, ok := staticWordsText(rest)
		if !ok {
			return 0
		}
		return homeValueSetByText(text, home, windows, depth+1)
	case "trap":
		if len(rest) < 2 {
			return 0
		}
		debug := false
		for _, word := range rest[1:] {
			value := projectPOSIXWord(word)
			debug = debug || (!value.Expands && value.Value == "DEBUG")
		}
		text, ok := staticWordsText(rest[:1])
		if !debug || !ok {
			return 0
		}
		return homeValueSetByText(text, home, windows, depth+1)
	}
	return 0
}

// homeValueSetByText is homeValueSetBy for the current-shell statements of
// eval or trap text. Text that does not parse runs nothing the shell could
// finish, so it sets nothing.
func homeValueSetByText(text, home string, windows bool, depth int) homeNames {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(text), "")
	if err != nil {
		return 0
	}
	var set homeNames
	for _, stmt := range currentShellStmts(file.Stmts) {
		set |= homeValueSetBy(stmt, home, windows, depth)
	}
	return set
}

// homeDeclOption reports a static declaration option that keeps the value
// as written: -x, -r, -g (or + to turn them off). -n makes a reference,
// -i, -l and -u rewrite the value and -a/-A make an array.
func homeDeclOption(value ArgumentFact) bool {
	if value.Expands || len(value.Value) < 2 || (value.Value[0] != '-' && value.Value[0] != '+') {
		return false
	}
	for _, letter := range value.Value[1:] {
		if !strings.ContainsRune("xrg", letter) {
			return false
		}
	}
	return true
}

// literalHomeAssign returns the name of NAME=value or NAME+=value for HOME,
// USER or LOGNAME when the value is literal and differs from the active
// one.
func literalHomeAssign(assign *syntax.Assign, home string, windows bool) homeNames {
	if assign == nil || assign.Name == nil || homeNameBit(assign.Name.Value) == 0 ||
		assign.Naked || assign.Index != nil || assign.Array != nil {
		return 0
	}
	value := ""
	if assign.Value != nil {
		projected := projectPOSIXWord(assign.Value)
		if projected.Expands {
			return 0
		}
		value = projected.Value
	}
	if (assign.Append && value != "") || (!assign.Append && homeValueDiffers(assign.Name.Value, value, home, windows)) {
		return homeNameBit(assign.Name.Value)
	}
	return 0
}

// homeValueDiffers reports a literal value of HOME (a path) or of USER or
// LOGNAME (the base name of the home) that is not the active one.
func homeValueDiffers(name, value, home string, windows bool) bool {
	want := home
	if name != "HOME" {
		want = path.Base(home)
	} else if windows {
		value = strings.ReplaceAll(value, `\`, "/")
		if len(value) >= 2 && value[0] == '/' && isASCIILetter(value[1]) && (len(value) == 2 || value[2] == '/') {
			value = value[1:2] + ":" + value[2:]
		}
		value = strings.TrimRight(value, "/")
	} else if value != "" {
		value = path.Clean(value)
	}
	if windows {
		return !strings.EqualFold(value, want)
	}
	return value != want
}

// arithmAssignedHomeNames returns the names among HOME, USER and LOGNAME
// that arithmetic assigns (HOME=1, USER+=1, ++LOGNAME).
func arithmAssignedHomeNames(expr syntax.ArithmExpr) homeNames {
	var set homeNames
	syntax.Walk(expr, func(node syntax.Node) bool {
		switch typed := node.(type) {
		case *syntax.BinaryArithm:
			switch typed.Op {
			case syntax.Assgn, syntax.AddAssgn, syntax.SubAssgn, syntax.MulAssgn, syntax.QuoAssgn,
				syntax.RemAssgn, syntax.AndAssgn, syntax.OrAssgn, syntax.XorAssgn, syntax.ShlAssgn,
				syntax.ShrAssgn:
				set |= arithmHomeName(typed.X)
			}
		case *syntax.UnaryArithm:
			if typed.Op == syntax.Inc || typed.Op == syntax.Dec {
				set |= arithmHomeName(typed.X)
			}
		}
		return true
	})
	return set
}

func arithmHomeName(expr syntax.ArithmExpr) homeNames {
	word, ok := expr.(*syntax.Word)
	if !ok {
		return 0
	}
	value := projectPOSIXWord(word)
	if value.Expands {
		return 0
	}
	return homeNameBit(value.Value)
}

// wordHomeNames returns the names among HOME, USER and LOGNAME a word
// expands.
func wordHomeNames(word *syntax.Word) homeNames {
	var set homeNames
	syntax.Walk(word, func(node syntax.Node) bool {
		if parameter, ok := node.(*syntax.ParamExp); ok && parameter.Param != nil {
			set |= homeNameBit(parameter.Param.Value)
		}
		return true
	})
	return set
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

// quotedOptionHome is an option word the trusted-home rewrite respells
// whole: the key, the active home and the path below it.
type quotedOptionHome struct {
	key, path, suffix string
}

// quotedOptionHomeRewrite reads an option word whose key or home word is
// quoted ("of=$HOME/f", 'of='$HOME/f, "of="${HOME}/f), which
// optionHomeRewriteWord does not split, as the key and the path under
// activeHome it writes (GAP-2399). The respelled word must stay a plain
// literal path.
func quotedOptionHomeRewrite(word *syntax.Word, activeHome string) (quotedOptionHome, bool) {
	if _, plain := optionHomeRewriteWord(word); plain {
		return quotedOptionHome{}, false
	}
	key, suffix, ok := optionHomeAnchoredPath(word)
	if !ok {
		return quotedOptionHome{}, false
	}
	path := strings.TrimRight(activeHome, "/") + suffix
	if !trustedPOSIXHomeLiteral.MatchString(path) {
		return quotedOptionHome{}, false
	}
	return quotedOptionHome{key: key, path: path, suffix: suffix}, true
}
