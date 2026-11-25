// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"errors"
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// parsePOSIX lowers a POSIX/bash command string into the neutral IR using the
// shared bounded parser (mvdan via shellparse). Any construct outside the
// allowlist becomes an UnknownNode with a reason, never a crash and never
// silence. Variable expansion is left to the walker (as word segments) so
// in-call assignments take effect (review PX-2).
func parsePOSIX(command string, o Options) *Script {
	s := &Script{Dialect: DialectPOSIX}
	file, ok := shellparse.Parse(command)
	if !ok || file == nil {
		if text, closed := comsubHeredocClose(command); closed {
			file, ok = shellparse.Parse(text)
		}
	}
	if !ok || file == nil {
		// The text from the line of the error on is not read (it may be a
		// construct bash takes and the parser does not): the unknown stays, and
		// the complete lines before it are lowered, because bash has run them.
		s.Unknowns = append(s.Unknowns, UnknownNode{Reason: ReasonInvalidSyntax})
		file, s.Unread = linesBeforeSyntaxError(command)
		if file == nil {
			return s
		}
	}
	w := &posixWalker{out: s}
	for _, st := range file.Stmts {
		w.stmt(st, false, false)
	}
	return s
}

// linesBeforeSyntaxError is what a non-interactive bash runs of a text with a
// syntax error: it reads and runs one complete command at a time, so every
// command on the lines before the line of the error has run, and nothing from
// that line on runs (bash -c 'echo A\nfi' prints A; 'echo A; fi' prints
// nothing). It returns the parse of those lines and the unread rest, or nil and
// the whole text. A command still open at the cut (an if whose fi is on the
// line of the error) did not run either: the cut moves to the line it starts
// on, a few times at most.
func linesBeforeSyntaxError(command string) (*syntax.File, string) {
	if shellparse.TooDeep(command) || len(command) > shellparse.MaxCommandBytes {
		return nil, command
	}
	text := command
	for range 4 {
		cut := lineStart(text, syntaxErrorLine(text))
		if cut <= 0 {
			return nil, command
		}
		text = text[:cut]
		if file, ok := shellparse.Parse(text); ok && file != nil {
			return file, command[cut:]
		}
	}
	return nil, command
}

// syntaxErrorLine is the 1-based line of the first bash syntax error in text,
// 0 when the parser gives no position.
func syntaxErrorLine(text string) (line int) {
	defer func() {
		if recover() != nil {
			line = 0
		}
	}()
	_, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(text), "")
	var pe syntax.ParseError
	var le syntax.LangError
	switch {
	case errors.As(err, &pe):
		return int(pe.Pos.Line())
	case errors.As(err, &le):
		return int(le.Pos.Line())
	}
	return 0
}

// lineStart is the byte offset where the 1-based line n of text starts; 0 for
// line 1 or an unknown line.
func lineStart(text string, n int) int {
	off := 0
	for i := 1; i < n; i++ {
		j := strings.IndexByte(text[off:], '\n')
		if j < 0 {
			return 0
		}
		off += j + 1
	}
	return off
}

// heredocOpener matches a here-document operator and its delimiter word.
var heredocOpener = regexp.MustCompile(`<<-?[ \t]*(?:'([^'\n]+)'|"([^"\n]+)"|\\?([A-Za-z0-9_.:+-]+))`)

// comsubHeredocClose is bash's reading of a here-document inside a command
// substitution: a line that starts with the delimiter and goes on to the
// substitution's closing ) or ` ends the here-document there (bash warns and
// runs it: x=$(cat <<EOF / hi / EOF) sets x to hi; the parser rejects it). It
// returns the text with a newline between the delimiter and the rest of such a
// line. Offsets after a split shift by one byte per split.
func comsubHeredocClose(command string) (string, bool) {
	if !strings.Contains(command, "<<") || (!strings.Contains(command, "$(") && !strings.Contains(command, "`")) {
		return "", false
	}
	delims := map[string]bool{}
	for _, m := range heredocOpener.FindAllStringSubmatchIndex(command, -1) {
		if m[0] > 0 && command[m[0]-1] == '<' {
			continue // a here-string (<<<), not a here-document
		}
		for g := 1; g <= 3; g++ {
			if m[2*g] >= 0 {
				delims[command[m[2*g]:m[2*g+1]]] = true
			}
		}
	}
	if len(delims) == 0 {
		return "", false
	}
	lines := strings.SplitAfter(command, "\n")
	changed := false
	for i := 1; i < len(lines); i++ {
		ln := lines[i]
		body := strings.TrimLeft(ln, "\t")
		for d := range delims {
			if !strings.HasPrefix(body, d) {
				continue
			}
			rest := body[len(d):]
			if r := strings.TrimLeft(rest, " \t"); r != "" && (r[0] == ')' || r[0] == '`') {
				lines[i] = ln[:len(ln)-len(rest)] + "\n" + rest
				changed = true
				break
			}
		}
	}
	if !changed {
		return "", false
	}
	return strings.Join(lines, ""), true
}

type posixWalker struct {
	out       *Script
	pipeDepth int
	pipeLast  bool
	// link is the && / || relation of the statement being lowered to the one
	// before it; every statement lowered while it is set carries it (round 8 F).
	link Op
	// dead, while set, is the guard of the right side of a provably false `&&`
	// or a provably true `||`: every statement lowered under it carries it as
	// its DeadGuard (GAP-0218).
	dead []string
	// bg counts the backgrounded statements being lowered: every command under
	// one runs in a child shell (Cmd.ChildList).
	bg int
	// marks maps a compound statement with redirects to the mark statement
	// lowered before its body.
	marks map[*syntax.Stmt]*Stmt
	// coproc counts the coprocess bodies being lowered: each runs
	// asynchronously in a child shell, like a background command (GAP-1508).
	coproc int
}

// linked lowers the right side of && / || with the link set.
func (w *posixWalker) linked(op Op, fn func()) {
	prev := w.link
	w.link = op
	fn()
	w.link = prev
}

// add appends a lowered statement, tagging it with the active && / || link.
func (w *posixWalker) add(st *Stmt) {
	if st.Link == OpNone {
		st.Link = w.link
	}
	if st.DeadGuard == nil && w.dead != nil {
		st.DeadGuard = w.dead
	}
	if w.bg > 0 {
		for _, c := range st.Cmds {
			c.ChildList = true
		}
	}
	w.out.Stmts = append(w.out.Stmts, st)
}

func (w *posixWalker) unknown(reason ReasonCode, node syntax.Node) {
	w.out.Unknowns = append(w.out.Unknowns, UnknownNode{Reason: reason, Span: span(node)})
}

func (w *posixWalker) stmt(st *syntax.Stmt, cond, pipeIn bool) {
	if st == nil {
		return
	}
	cond = cond || st.Negated
	if st.Background {
		w.bg++
		defer func() { w.bg-- }()
	}
	if len(st.Redirs) > 0 {
		switch st.Cmd.(type) {
		case *syntax.Block, *syntax.IfClause, *syntax.WhileClause, *syntax.ForClause, *syntax.CaseClause:
			mark := &Stmt{ExecMark: true, Span: span(st)}
			w.add(mark)
			if w.marks == nil {
				w.marks = map[*syntax.Stmt]*Stmt{}
			}
			w.marks[st] = mark
		}
	}
	switch cmd := st.Cmd.(type) {
	case nil:
		w.emitCall(st, nil, cond, pipeIn)
	case *syntax.CallExpr:
		w.emitCall(st, cmd, cond, pipeIn)
	case *syntax.BinaryCmd:
		w.binary(st, cmd, cond)
	case *syntax.Block:
		for _, inner := range cmd.Stmts {
			w.stmt(inner, cond, false)
		}
		w.compoundRedirs(st, cond)
	case *syntax.Subshell:
		// A subshell runs in a child; cd inside it does not escape. Lower it to
		// one Cmd carrying a nested script so the walker can scope cwd/env.
		sub := &Script{Dialect: DialectPOSIX}
		nw := &posixWalker{out: sub}
		for _, inner := range cmd.Stmts {
			nw.stmt(inner, cond, false)
		}
		c := &Cmd{Sub: sub, Cond: cond, Span: span(st)}
		w.redirs(st, c)
		w.add(&Stmt{Cmds: []*Cmd{c}, Cond: cond, Span: span(st)})
	case *syntax.IfClause:
		w.ifClause(cmd, cond)
		w.compoundRedirs(st, cond)
	case *syntax.WhileClause:
		for _, inner := range cmd.Cond {
			w.stmt(inner, cond, false)
		}
		w.loopReadInput(st, cmd)
		for _, inner := range cmd.Do {
			w.stmt(inner, true, false)
		}
		w.compoundRedirs(st, cond)
	case *syntax.ForClause:
		if cmd.Loop != nil {
			if wl, ok := cmd.Loop.(*syntax.WordIter); ok {
				for _, word := range wl.Items {
					tmp := &Cmd{}
					w.scanCmdSubsts(word, tmp)
					for _, sub := range tmp.Nested {
						w.add(&Stmt{Cmds: []*Cmd{{Sub: sub, Cond: true}}, Cond: true})
					}
				}
				// the loop rebinds its variable: drop its static value.
				if wl.Name != nil && wl.Name.Value != "" {
					w.add(&Stmt{Cmds: []*Cmd{{Assigns: []Assign{{Name: wl.Name.Value, Unbind: true}}}}})
				}
			}
		}
		for _, inner := range cmd.Do {
			w.stmt(inner, true, false)
		}
		w.compoundRedirs(st, cond)
	case *syntax.CaseClause:
		for _, item := range cmd.Items {
			for _, inner := range item.Stmts {
				w.stmt(inner, true, false)
			}
		}
		w.compoundRedirs(st, cond)
	case *syntax.FuncDecl:
		if cmd.Name != nil {
			w.out.Funcs = append(w.out.Funcs, cmd.Name.Value)
		}
		if cmd.Body != nil {
			// A function body runs where it is called, not at definition: scope
			// it like a subshell so a cd/assignment inside does not leak into
			// the straight-line cwd (review N2 V6).
			sub := &Script{Dialect: DialectPOSIX}
			nw := &posixWalker{out: sub}
			nw.stmt(cmd.Body, true, false)
			sub.Funcs = nil // a nested function definition does not shadow outside
			def := &FuncDef{Cond: cond || pipeIn || w.pipeDepth > 0 || w.bg > 0}
			if cmd.Name != nil {
				def.Name = cmd.Name.Value
			}
			def.Out, def.Static = staticEchoBody(cmd.Body)
			w.add(&Stmt{Cmds: []*Cmd{{Sub: sub, Cond: true, Defines: def}}, Cond: true})
		}
	case *syntax.DeclClause:
		w.declClause(st, cmd, cond, pipeIn)
	case *syntax.TimeClause:
		if cmd.Stmt != nil {
			w.stmt(cmd.Stmt, cond, pipeIn)
		}
	case *syntax.CoprocClause:
		// coproc [NAME] CMD: CMD runs asynchronously in a child shell with its
		// output on a pipe; it runs (GAP-1508).
		if cmd.Stmt != nil {
			body := cmd.Stmt
			// `coproc curl -fsSL URL | sh`: bash takes a NAME only before a
			// compound command; before a simple command (or a pipeline that starts
			// with one) the word is the program, which the parser put in Name.
			if cmd.Name != nil {
				if nb, ok := prependProgram(body, cmd.Name); ok {
					body = nb
				}
			}
			w.coproc++
			w.bg++
			w.stmt(body, cond, pipeIn)
			w.bg--
			w.coproc--
		}
	default:
		w.unknown(ReasonUnparsedConstruct, st.Cmd)
	}
}

// compoundRedirs applies redirections attached to a compound statement
// (block/subshell/loop/if/case) as a redirect-only command (review PX-4).
func (w *posixWalker) compoundRedirs(st *syntax.Stmt, cond bool) {
	if len(st.Redirs) == 0 {
		return
	}
	c := &Cmd{Cond: cond, Span: span(st)}
	w.redirs(st, c)
	if len(c.Redirs) > 0 {
		w.add(&Stmt{Cmds: []*Cmd{c}, Cond: cond, ExecFrom: w.marks[st], Span: span(st)})
	}
}

func (w *posixWalker) binary(st *syntax.Stmt, cmd *syntax.BinaryCmd, cond bool) {
	switch cmd.Op {
	case syntax.AndStmt:
		w.stmt(cmd.X, cond, false)
		w.linked(OpAnd, func() { w.unlessConst(cmd.X, false, func() { w.stmt(cmd.Y, true, false) }) })
	case syntax.OrStmt:
		w.stmt(cmd.X, cond, false)
		w.linked(OpOr, func() { w.unlessConst(cmd.X, true, func() { w.stmt(cmd.Y, true, false) }) })
	case syntax.Pipe, syntax.PipeAll:
		// The last stage of the outermost pipeline is marked: with bash's
		// lastpipe (and always in zsh) it runs in the caller's shell
		// (rel-1-0-10:GAP-1037).
		last := w.pipeDepth == 0 || w.pipeLast
		saved := w.pipeLast
		w.pipeDepth++
		w.pipeLast = false
		w.stmt(cmd.X, cond, false)
		w.pipeLast = last
		w.stmt(cmd.Y, cond, true)
		w.pipeLast = saved
		w.pipeDepth--
	default:
		w.unknown(ReasonUnparsedConstruct, cmd)
	}
}

// unlessConst lowers the right side of && / || (fn). When the left side x has
// the constant status that skips it (false before &&, true before ||), the
// right side never runs: it is lowered with the guard's names as its dead
// guard (GAP-0218).
func (w *posixWalker) unlessConst(x *syntax.Stmt, skipWhenSuccess bool, fn func()) {
	success, names, ok := constStatus(x)
	if !ok || success != skipWhenSuccess {
		fn()
		return
	}
	prev := w.dead
	w.dead = append(append([]string(nil), prev...), names...)
	fn()
	w.dead = prev
}

// constStatus is the exit status of a statement made only of the builtins
// true, false and : (with ! and && / || between them), with the names it
// relies on. false fails whatever its arguments, assignments and redirects do
// (a failed expansion or redirect fails too); true and : succeed only bare,
// since an argument expansion or a redirect can fail. ok is false for anything
// else, and for a background or coprocess statement (its status is 0).
func constStatus(st *syntax.Stmt) (success bool, names []string, ok bool) {
	if st == nil || st.Background || st.Coprocess {
		return false, nil, false
	}
	switch c := st.Cmd.(type) {
	case *syntax.CallExpr:
		if len(c.Args) == 0 {
			return false, nil, false
		}
		switch lit := c.Args[0].Lit(); {
		case lit == "false":
			success, names = false, []string{lit}
		case (lit == "true" || lit == ":") && len(c.Args) == 1 && len(c.Assigns) == 0 && len(st.Redirs) == 0:
			success, names = true, []string{lit}
		default:
			return false, nil, false
		}
	case *syntax.BinaryCmd:
		if c.Op != syntax.AndStmt && c.Op != syntax.OrStmt {
			return false, nil, false
		}
		xs, xn, xok := constStatus(c.X)
		if !xok {
			return false, nil, false
		}
		success, names = xs, xn
		// The right side runs after a true left side of &&, a false one of ||.
		if xs == (c.Op == syntax.AndStmt) {
			ys, yn, yok := constStatus(c.Y)
			if !yok {
				return false, nil, false
			}
			success, names = ys, append(append([]string(nil), xn...), yn...)
		}
	default:
		return false, nil, false
	}
	if st.Negated {
		success = !success
	}
	return success, names, true
}

func (w *posixWalker) ifClause(cmd *syntax.IfClause, cond bool) {
	for _, inner := range cmd.Cond {
		w.stmt(inner, cond, false)
	}
	for _, inner := range cmd.Then {
		w.stmt(inner, true, false)
	}
	if cmd.Else != nil {
		// An elif condition runs only when the conditions before it failed: it is
		// conditional, so an exit or set -n in it does not end the shell for
		// what follows the if (t-obs-b2 batch review P2-1).
		w.ifClause(cmd.Else, true)
	}
}

func (w *posixWalker) declClause(st *syntax.Stmt, cmd *syntax.DeclClause, cond, pipeIn bool) {
	c := &Cmd{Cond: cond, PipeIn: pipeIn, Pipeline: w.pipeDepth > 0, PipeLast: w.pipeDepth > 0 && w.pipeLast, Span: span(cmd)}
	// Only `export` (or declare/typeset -x) puts a variable in the environment of
	// the commands that follow; a plain declare/local/readonly does not (round 8 E).
	isExport := cmd.Variant != nil && cmd.Variant.Value == "export"
	exported := isExport
	unexport, attr, nameref := false, false, false
	for _, a := range cmd.Args {
		if a.Name == nil && a.Value != nil {
			lit := a.Value.Lit()
			if lit == "" || (lit[0] != '-' && lit[0] != '+') {
				// an operand that is not a plain NAME[=value] (a quoted or computed
				// name): what it declares is not known.
				w.unknown(ReasonOpaqueCode, cmd)
				continue
			}
			switch {
			case strings.HasPrefix(lit, "+") && strings.Contains(lit, "x"):
				unexport = true // declare +x / typeset +x
			case strings.HasPrefix(lit, "-") && !strings.HasPrefix(lit, "--") && strings.Contains(lit, "x"):
				exported = true
			case isExport && strings.HasPrefix(lit, "-") && strings.Contains(lit, "n"):
				unexport, exported = true, false // export -n NAME
			}
			if !isExport && strings.ContainsAny(lit[1:], "n") && lit[0] == '-' {
				nameref = true
			}
			// any attribute other than export / global / readonly / print changes
			// what the variable holds or is.
			if strings.ContainsAny(lit[1:], "luciaAnftC") && (!isExport || lit != "-n") {
				attr = true
			}
		}
	}
	for _, a := range cmd.Args {
		if a.Name == nil {
			continue
		}
		if a.Index != nil || a.Array != nil {
			w.unknown(ReasonOpaqueCode, cmd) // a subscript or array body is evaluated
		}
		as := Assign{Name: a.Name.Value, Exported: exported && !unexport, Unexport: unexport, Append: a.Append, Attr: attr, NameRef: nameref}
		if a.Value != nil {
			as.ValueWord = w.word(a.Value)
			w.scanCmdSubsts(a.Value, c)
		} else {
			as.ValueWord = Word{Static: true}
			as.NoValue = true
		}
		c.Assigns = append(c.Assigns, as)
	}
	w.redirs(st, c)
	w.add(&Stmt{Cmds: []*Cmd{c}, Cond: cond, Span: span(cmd)})
}

func (w *posixWalker) emitCall(st *syntax.Stmt, call *syntax.CallExpr, cond, pipeIn bool) {
	c := &Cmd{Cond: cond, PipeIn: pipeIn, Pipeline: w.pipeDepth > 0, PipeLast: w.pipeDepth > 0 && w.pipeLast, Async: st.Background || w.coproc > 0, Span: span(st)}
	if call != nil {
		for _, a := range call.Assigns {
			if a.Name == nil {
				continue
			}
			if a.Index != nil || a.Array != nil {
				w.unknown(ReasonOpaqueCode, st) // `a[$(x)]=v`, `a=($(x))`: the subscript / elements run
			}
			as := Assign{Name: a.Name.Value, Append: a.Append}
			if a.Value != nil {
				as.ValueWord = w.word(a.Value)
				w.scanCmdSubsts(a.Value, c)
			} else {
				as.ValueWord = Word{Static: true}
			}
			c.Assigns = append(c.Assigns, as)
		}
		for _, arg := range call.Args {
			n := len(c.Nested)
			w.scanCmdSubsts(arg, c)
			// Brace expansion is the shell's first word expansion: a {a,b}
			// list becomes its words before ~ and variables are read, so each
			// alternative is its own operand (DET111 R1, GAP-0662).
			if alts, ok := braceWords(arg); ok {
				for _, alt := range alts {
					wd := w.word(alt)
					wd.Span = span(arg)
					c.Words = append(c.Words, wd)
				}
				continue
			}
			wd := w.word(arg)
			if soleInputProcSubst(arg) && len(c.Nested) == n+1 {
				wd.ProcSub = c.Nested[n]
			}
			c.Words = append(c.Words, wd)
		}
	}
	w.redirs(st, c)
	w.add(&Stmt{Cmds: []*Cmd{c}, Cond: cond, Background: st.Background, Span: span(st)})
}

// scanCmdSubsts recursively collects every command substitution anywhere in a
// word (including inside double quotes) as a nested script (review PX-3).
func (w *posixWalker) scanCmdSubsts(word *syntax.Word, c *Cmd) {
	if word == nil {
		return
	}
	syntax.Walk(word, func(n syntax.Node) bool {
		var stmts []*syntax.Stmt
		switch n2 := n.(type) {
		case *syntax.CmdSubst:
			stmts = n2.Stmts
		case *syntax.ProcSubst:
			stmts = n2.Stmts
		}
		if stmts != nil {
			sub := &Script{Dialect: DialectPOSIX}
			nw := &posixWalker{out: sub}
			for _, inner := range stmts {
				nw.stmt(inner, true, false)
			}
			c.Nested = append(c.Nested, sub)
			// Do not descend again: the nested walker already handled every
			// substitution inside this one. Returning true here re-walks them,
			// which is O(4^depth) (review R3-1 / J7).
			return false
		}
		return true
	})
}

func (w *posixWalker) redirs(st *syntax.Stmt, c *Cmd) {
	for _, r := range st.Redirs {
		if r == nil {
			continue
		}
		red := Redir{FD: -1}
		if r.N != nil {
			if n, ok := atoiSafe(r.N.Value); ok {
				red.FD = n
			}
		}
		switch r.Op {
		case syntax.RdrOut:
			red.Op = RedirWrite
			if red.FD < 0 {
				red.FD = 1
			}
		case syntax.AppOut:
			red.Op = RedirAppend
			if red.FD < 0 {
				red.FD = 1
			}
		case syntax.RdrIn:
			red.Op = RedirRead
		case syntax.Hdoc, syntax.DashHdoc:
			red.Op = RedirHeredoc
		case syntax.WordHdoc:
			red.Op = RedirHereString
		case syntax.RdrClob:
			red.Op = RedirClobber
			if red.FD < 0 {
				red.FD = 1
			}
		case syntax.DplOut, syntax.DplIn:
			// `>&word`: a numeric word is an fd dup (ignored); a file word is a
			// stdout+stderr file write (review N9 R4/V20c).
			red.Op = RedirDup
			if r.Op == syntax.DplOut && r.Word != nil {
				if tw := w.word(r.Word); tw.Static && !allDigits(tw.Value) && tw.Value != "-" {
					red.Op = RedirWrite
					red.FD = 1
				}
			}
		case syntax.RdrAll:
			red.Op = RedirWrite
			red.FD = 1
		case syntax.AppAll:
			red.Op = RedirAppend
			red.FD = 1
		default:
			red.Op = RedirWrite
		}
		if r.Word != nil {
			red.Target = w.word(r.Word)
			n := len(c.Nested)
			w.scanCmdSubsts(r.Word, c)
			if r.Op == syntax.RdrIn && soleInputProcSubst(r.Word) && len(c.Nested) == n+1 {
				red.Target.ProcSub = c.Nested[n]
			}
		}
		// A here-string's text is the word after <<<; it is the body of that
		// redirect (round 8 R: a shell fed `<<< "$(..)"` must not look empty).
		if r.Op == syntax.WordHdoc && r.Word != nil {
			red.Body, red.BodyExpands = heredocBody(r.Word, bodyHereString)
		}
		if r.Hdoc != nil {
			mode := bodyHeredocExpanding
			if quotedDelimiter(r.Word) {
				mode = bodyHeredocLiteral
			}
			red.Body, red.BodyExpands = heredocBody(r.Hdoc, mode)
			// A command substitution in an expanding heredoc body runs (review D
			// PX-3: C40/C41/V22). An unquoted-delimiter heredoc with $( ) / `` is
			// walked; a quoted-delimiter body has no CmdSubst node, so nothing is
			// added.
			w.scanCmdSubsts(r.Hdoc, c)
		}
		c.Redirs = append(c.Redirs, red)
	}
}

// word builds the neutral Word. A word of only literals and simple $VAR / ${VAR}
// expansions gets Segs for the walker to resolve; anything with a command
// substitution, arithmetic, process substitution or a complex parameter op is
// dynamic (no Segs, a Reason).
func (w *posixWalker) word(word *syntax.Word) Word {
	if word == nil {
		return Word{Reason: ReasonDynamicExpansion}
	}
	out := Word{Span: span(word)}
	var segs []WordSeg
	addLit := func(s string, quoted, glob bool) { segs = append(segs, WordSeg{Lit: s, Quoted: quoted, Glob: glob}) }
	dynamic := func(reason ReasonCode) {
		out.Static = false
		out.Segs = nil
		out.Reason = reason
	}
	for _, part := range word.Parts {
		if out.Reason != "" {
			break
		}
		switch p := part.(type) {
		case *syntax.Lit:
			// An escaped metachar (\*) is a literal, not a glob: mark the
			// segment quoted so resolveWord does not treat it as a pattern
			// (review PX-6, Q5).
			addLit(unescapePOSIX(p.Value, false), false, hasUnescapedMeta(p.Value))
		case *syntax.SglQuoted:
			if p.Dollar {
				// ANSI-C quoting $'...\x72...': decoded as bash decodes it, so a
				// program name or a path spelled with escapes is read
				// (GAP-1629); an escape the decoder does not take is not a
				// canonical value (review R3-7).
				if v, ok := decodeANSIC(p.Value); ok {
					addLit(v, true, false)
					out.Quoted = true
					continue
				}
				dynamic(ReasonNonCanonicalPath)
				continue
			}
			addLit(p.Value, true, false)
			out.Quoted = true
		case *syntax.DblQuoted:
			out.Quoted = true
			for _, inner := range p.Parts {
				switch ip := inner.(type) {
				case *syntax.Lit:
					addLit(unescapePOSIX(ip.Value, true), true, false)
				case *syntax.ParamExp:
					if seg, ok := paramSeg(ip, true); ok {
						segs = append(segs, seg)
					} else {
						dynamic(ReasonDynamicExpansion)
					}
				case *syntax.CmdSubst:
					if pwdSubst(ip) {
						segs = append(segs, WordSeg{Subst: "pwd", Quoted: true})
					} else {
						dynamic(ReasonDynamicExpansion)
					}
				default:
					dynamic(ReasonDynamicExpansion)
				}
			}
		case *syntax.ParamExp:
			if seg, ok := paramSeg(p, false); ok {
				segs = append(segs, seg)
			} else {
				dynamic(ReasonDynamicExpansion)
			}
		case *syntax.ArithmExp:
			// an arithmetic expansion evaluates variable values as expressions, and
			// an expression can carry a subscript with a command substitution
			w.unknown(ReasonOpaqueCode, p)
			dynamic(ReasonDynamicExpansion)
		case *syntax.CmdSubst:
			if pwdSubst(p) {
				segs = append(segs, WordSeg{Subst: "pwd"})
			} else {
				dynamic(ReasonDynamicExpansion)
			}
		case *syntax.ExtGlob:
			dynamic(ReasonDynamicExpansion)
		case *syntax.ProcSubst:
			dynamic(ReasonUnparsedConstruct)
		default:
			dynamic(ReasonDynamicExpansion)
		}
	}
	if out.Reason != "" {
		out.Tail = literalTail(word)
		return out
	}
	out.Segs = segs
	// A word is fully static (Value set) only when it has no variable segment.
	hasVar := false
	var b strings.Builder
	for _, s := range segs {
		if s.Var != "" {
			hasVar = true
			break
		}
		b.WriteString(s.Lit)
	}
	if !hasVar {
		out.Static = true
		out.Value = b.String()
	}
	return out
}

// paramSeg lowers a parameter expansion the walker can evaluate: a plain
// $NAME / ${NAME}, or one operator with static operands (pattern removal,
// literal replacement, a literal substring). Anything else is dynamic.
func paramSeg(p *syntax.ParamExp, quoted bool) (WordSeg, bool) {
	if name, ok := simpleParam(p); ok {
		return WordSeg{Var: name, Quoted: quoted}, true
	}
	if p == nil || p.Param == nil || p.Excl || p.Length || p.Width || p.Index != nil || p.Names != 0 {
		return WordSeg{}, false
	}
	seg := WordSeg{Var: p.Param.Value, Quoted: quoted}
	switch {
	case p.Exp != nil && p.Repl == nil && p.Slice == nil:
		pat, ok := staticWordText(p.Exp.Word)
		if !ok {
			return WordSeg{}, false
		}
		switch p.Exp.Op {
		case syntax.RemSmallPrefix:
			seg.Op = &ParamOp{Kind: "#", Pat: pat}
		case syntax.RemLargePrefix:
			seg.Op = &ParamOp{Kind: "##", Pat: pat}
		case syntax.RemSmallSuffix:
			seg.Op = &ParamOp{Kind: "%", Pat: pat}
		case syntax.RemLargeSuffix:
			seg.Op = &ParamOp{Kind: "%%", Pat: pat}
		default:
			return WordSeg{}, false
		}
	case p.Repl != nil && p.Exp == nil && p.Slice == nil:
		// A literal pattern, optionally anchored at the start (/#) or the
		// end (/%) of the value, with backslash-escaped literal characters
		// (${PWD/%\/proj/}). A glob character keeps the word dynamic
		// (rel-1-0-10:GAP-1244).
		kind := "/"
		if p.Repl.All {
			kind = "//"
		}
		raw, ok := rawLiteralText(p.Repl.Orig)
		if ok && raw != "" && (raw[0] == '#' || raw[0] == '%') {
			if p.Repl.All {
				return WordSeg{}, false
			}
			kind, raw = "/"+raw[:1], raw[1:]
		}
		orig, ok1 := unescapeLiteralPattern(raw)
		with, ok2 := staticWordText(p.Repl.With)
		if !ok || !ok1 || !ok2 || strings.ContainsAny(orig, "*?[") || orig == "" && (kind == "/" || kind == "//") {
			return WordSeg{}, false
		}
		seg.Op = &ParamOp{Kind: kind, Pat: orig, With: with}
	case p.Slice != nil && p.Exp == nil && p.Repl == nil:
		// ${NAME:OFF} and ${NAME:OFF:LEN}: an empty offset is 0, and a
		// negative offset or length counts from the end of the value
		// (${PWD:0:-5}, ${PWD: -5}, rel-1-0-10:GAP-1244).
		off, ok := 0, true
		if p.Slice.Offset != nil {
			off, ok = signedArithLiteral(p.Slice.Offset, true)
		}
		if !ok {
			return WordSeg{}, false
		}
		seg.Op = &ParamOp{Kind: ":", Off: off}
		if p.Slice.Length != nil {
			n, ok := signedArithLiteral(p.Slice.Length, false)
			if !ok {
				return WordSeg{}, false
			}
			seg.Op.Len, seg.Op.HasLen = n, true
		}
	default:
		return WordSeg{}, false
	}
	return seg, true
}

// staticWordText is the text of a word of literals only (nil is ""). A
// pattern word keeps its glob metacharacters; a quoted one is literal, which
// a pattern matcher would read differently, so quoting is refused.
func staticWordText(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", true
	}
	var b strings.Builder
	for _, part := range w.Parts {
		lit, ok := part.(*syntax.Lit)
		if !ok || strings.ContainsAny(lit.Value, `\$`+"`") {
			return "", false
		}
		b.WriteString(lit.Value)
	}
	return b.String(), true
}

// rawLiteralText is the text of a word of literals only, backslashes kept.
func rawLiteralText(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", true
	}
	var b strings.Builder
	for _, part := range w.Parts {
		lit, ok := part.(*syntax.Lit)
		if !ok || strings.ContainsAny(lit.Value, "$`") {
			return "", false
		}
		b.WriteString(lit.Value)
	}
	return b.String(), true
}

// unescapeLiteralPattern drops the backslash before a character that is no
// glob metacharacter (the character is literal). A backslash before a glob
// character or at the end refuses the pattern.
func unescapeLiteralPattern(s string) (string, bool) {
	if !strings.Contains(s, `\`) {
		return s, true
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+1 == len(s) || strings.IndexByte(`*?[]\`, s[i+1]) >= 0 {
			return "", false
		}
		i++
		b.WriteByte(s[i])
	}
	return b.String(), true
}

// signedArithLiteral is a decimal literal of an arithmetic slot, with an
// optional leading minus (-5) or a parenthesized one ((-5)). An empty word
// is 0 when empty is allowed (the omitted offset of ${NAME::LEN}).
func signedArithLiteral(x syntax.ArithmExpr, empty bool) (int, bool) {
	switch e := x.(type) {
	case *syntax.ParenArithm:
		return signedArithLiteral(e.X, false)
	case *syntax.UnaryArithm:
		if e.Op != syntax.Minus || e.Post {
			return 0, false
		}
		n, ok := arithLiteral(e.X)
		return -n, ok
	case *syntax.Word:
		if empty && len(e.Parts) == 0 {
			return 0, true
		}
	}
	return arithLiteral(x)
}

// arithLiteral is a non-negative decimal literal of an arithmetic slot.
func arithLiteral(x syntax.ArithmExpr) (int, bool) {
	w, ok := x.(*syntax.Word)
	if !ok {
		return 0, false
	}
	s, ok := staticWordText(w)
	if !ok || s == "" || len(s) > 6 {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

// pwdSubst reports $(pwd), `pwd` or $(pwd -L): one plain call of pwd with no
// assignment, redirect or other word, whose output is the logical working
// folder. pwd -P (physical) is not read.
func pwdSubst(cs *syntax.CmdSubst) bool {
	if cs == nil || len(cs.Stmts) != 1 {
		return false
	}
	st := cs.Stmts[0]
	if st.Negated || st.Background || st.Coprocess || len(st.Redirs) > 0 {
		return false
	}
	call, ok := st.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) > 0 || len(call.Args) == 0 || len(call.Args) > 2 {
		return false
	}
	if call.Args[0].Lit() != "pwd" {
		return false
	}
	return len(call.Args) == 1 || call.Args[1].Lit() == "-L"
}

// staticEchoBody is the output of a function body that is one echo of one
// static word ({ echo /tmp; } or ( echo /tmp )), with the trailing newline a
// command substitution drops: an unquoted literal with no escape, expansion,
// glob, brace, leading ~ (tilde expansion) or leading - (an echo option), so
// every echo prints it as spelled (rel-1-0-10:GAP-1043).
func staticEchoBody(body *syntax.Stmt) (string, bool) {
	if body == nil || body.Negated || body.Background || len(body.Redirs) > 0 {
		return "", false
	}
	var stmts []*syntax.Stmt
	switch b := body.Cmd.(type) {
	case *syntax.Block:
		stmts = b.Stmts
	case *syntax.Subshell:
		stmts = b.Stmts
	}
	if len(stmts) != 1 {
		return "", false
	}
	st := stmts[0]
	if st.Negated || st.Background || st.Coprocess || len(st.Redirs) > 0 {
		return "", false
	}
	call, ok := st.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) > 0 || len(call.Args) != 2 || call.Args[0].Lit() != "echo" {
		return "", false
	}
	out, ok := staticWordText(call.Args[1])
	if !ok || out == "" || out[0] == '-' || out[0] == '~' || looksGlob(out) {
		return "", false
	}
	return out, true
}

// literalTail is the literal text after the last part of word that is not a
// literal (only unquoted, single-quoted and double-quoted literal runs count).
func literalTail(word *syntax.Word) string {
	var tail []string
	for i := len(word.Parts) - 1; i >= 0; i-- {
		switch p := word.Parts[i].(type) {
		case *syntax.Lit:
			tail = append(tail, unescapePOSIX(p.Value, false))
		case *syntax.SglQuoted:
			if p.Dollar {
				return joinReversed(tail)
			}
			tail = append(tail, p.Value)
		default:
			return joinReversed(tail)
		}
	}
	return joinReversed(tail)
}

func joinReversed(parts []string) string {
	var b strings.Builder
	for i := len(parts) - 1; i >= 0; i-- {
		b.WriteString(parts[i])
	}
	return b.String()
}

// simpleParam returns the variable name for a plain $NAME / ${NAME} with no
// modifier, index, slice, replacement or length operator.
func simpleParam(p *syntax.ParamExp) (string, bool) {
	if p == nil || p.Param == nil || p.Excl || p.Length || p.Width ||
		p.Index != nil || p.Slice != nil || p.Repl != nil || p.Exp != nil || p.Names != 0 {
		return "", false
	}
	return p.Param.Value, true
}

func span(n syntax.Node) [2]int {
	if n == nil {
		return [2]int{}
	}
	return [2]int{int(n.Pos().Offset()), int(n.End().Offset())}
}

// bodyMode is how the shell reads the text of a here-string or here-document.
type bodyMode uint8

const (
	bodyHereString       bodyMode = iota // <<< WORD: quote removal of the word
	bodyHeredocExpanding                 // <<E: \$ \` \\ and \newline are escapes
	bodyHeredocLiteral                   // <<'E': the body as written
)

// quotedDelimiter reports a here-document delimiter with any quoting ('E',
// "E", \E, E”): its body is literal.
func quotedDelimiter(w *syntax.Word) bool {
	if w == nil {
		return false
	}
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.SglQuoted, *syntax.DblQuoted:
			return true
		case *syntax.Lit:
			if strings.Contains(p.Value, `\`) {
				return true
			}
		}
	}
	return false
}

// heredocUnescape is the backslash rule of an expanding here-document body:
// \$, \`, \\ lose the backslash, \newline joins the lines, any other
// backslash stays.
func heredocUnescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '$', '`', '\\':
				i++
				b.WriteByte(s[i])
				continue
			case '\n':
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// heredocBody is the text a here-string or here-document feeds, read the way
// the shell reads it (mode); the parser keeps every backslash of the source,
// so a body read raw is not what the shell runs (bash <<E / rm -rf \\ ...,
// bash <<< rm\ -rf\ ...). expands is true when a part is not static.
func heredocBody(w *syntax.Word, mode bodyMode) (string, bool) {
	if w == nil {
		return "", false
	}
	var b strings.Builder
	expands := false
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			switch mode {
			case bodyHereString:
				b.WriteString(unescapePOSIX(p.Value, false))
			case bodyHeredocExpanding:
				b.WriteString(heredocUnescape(p.Value))
			default:
				b.WriteString(p.Value)
			}
		case *syntax.SglQuoted:
			if p.Dollar {
				v, ok := decodeANSIC(p.Value)
				if !ok {
					expands = true
					continue
				}
				b.WriteString(v)
				continue
			}
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			// "plain text" is static; anything with an expansion inside is not.
			for _, q := range p.Parts {
				if l, ok := q.(*syntax.Lit); ok {
					if mode == bodyHereString {
						b.WriteString(unescapePOSIX(l.Value, true))
					} else {
						b.WriteString(l.Value)
					}
				} else {
					expands = true
				}
			}
		default:
			expands = true
		}
	}
	return b.String(), expands
}

// unescapePOSIX removes shell backslash escapes. Inside double quotes only a
// few characters are escapable, so a backslash before any other byte is literal
// (review PX-8b: `"/tmp/a\b"` keeps the backslash).
func unescapePOSIX(s string, inDoubleQuote bool) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			nxt := s[i+1]
			if inDoubleQuote && nxt != '"' && nxt != '\\' && nxt != '$' && nxt != '`' {
				b.WriteByte('\\')
				continue
			}
			i++
			b.WriteByte(nxt)
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func atoiSafe(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}

// maxBraceWords bounds the words one brace-expanded argument becomes; a larger
// expansion stays one glob word.
const maxBraceWords = 64

// braceWords is the brace expansion of one argument, ok false when it has no
// brace group or expands past maxBraceWords (it then stays a glob word).
func braceWords(arg *syntax.Word) (words []*syntax.Word, ok bool) {
	if arg == nil || !strings.Contains(arg.Lit(), "{") && !wordLitHasBrace(arg) {
		return nil, false
	}
	if shellparse.BraceFieldsTooLarge(arg) {
		return nil, false
	}
	split := *arg // SplitBraces replaces the Parts slice, never the parts
	if !syntax.SplitBraces(&split) {
		return nil, false
	}
	defer func() {
		if recover() != nil {
			words, ok = nil, false // a library panic: keep the glob word
		}
	}()
	words = expand.Braces(&split)
	if len(words) < 2 || len(words) > maxBraceWords {
		return nil, false
	}
	return words, true
}

// wordLitHasBrace reports an unquoted literal part with a brace, the only place
// a brace group can start.
func wordLitHasBrace(arg *syntax.Word) bool {
	for _, p := range arg.Parts {
		if lit, ok := p.(*syntax.Lit); ok && strings.Contains(lit.Value, "{") {
			return true
		}
	}
	return false
}

// hasUnescapedMeta reports whether a raw POSIX literal has an unescaped glob
// metacharacter (*?[) or a brace list {a,b}. Escaped characters are masked to a
// non-meta placeholder first, so an escaped \* is literal while an unescaped
// {a,b} alongside it still globs (review N10).
func hasUnescapedMeta(raw string) bool {
	if !strings.Contains(raw, `\`) {
		return looksGlob(raw)
	}
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\\' && i+1 < len(raw) {
			i++
			b.WriteByte('x') // mask the escaped char
			continue
		}
		b.WriteByte(raw[i])
	}
	return looksGlob(b.String())
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// soleInputProcSubst reports a word that is exactly one input process
// substitution <(...).
func soleInputProcSubst(word *syntax.Word) bool {
	if word == nil || len(word.Parts) != 1 {
		return false
	}
	ps, ok := word.Parts[0].(*syntax.ProcSubst)
	return ok && ps.Op == syntax.CmdIn
}

// loopReadInput gives the read of `while read [-r] NAME; do ...; done <<< W`
// (or <<E) the loop's input, so the body sees NAME bound (GAP-1554).
func (w *posixWalker) loopReadInput(st *syntax.Stmt, cmd *syntax.WhileClause) {
	if len(cmd.Cond) != 1 || len(w.out.Stmts) == 0 {
		return
	}
	call, ok := cmd.Cond[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 || call.Args[0].Lit() != "read" || len(cmd.Cond[0].Redirs) > 0 {
		return
	}
	var in []*syntax.Redirect
	for _, r := range st.Redirs {
		if r != nil && r.N == nil && (r.Op == syntax.WordHdoc || r.Op == syntax.Hdoc || r.Op == syntax.DashHdoc) {
			in = append(in, r)
		}
	}
	last := w.out.Stmts[len(w.out.Stmts)-1]
	if len(in) == 0 || len(last.Cmds) != 1 || len(last.Cmds[0].Words) == 0 || last.Cmds[0].Words[0].Value != "read" {
		return
	}
	tmp := &Cmd{}
	w.redirs(&syntax.Stmt{Redirs: in}, tmp)
	last.Cmds[0].Redirs = append(last.Cmds[0].Redirs, tmp.Redirs...)
}

// decodeANSIC decodes the body of a bash $'...' word. ok is false for a NUL
// (bash ends the word there) or a truncated escape.
func decodeANSIC(s string) (string, bool) {
	if !strings.Contains(s, `\`) {
		return s, true
	}
	var b strings.Builder
	hexVal := func(c byte) int {
		switch {
		case c >= '0' && c <= '9':
			return int(c - '0')
		case c >= 'a' && c <= 'f':
			return int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			return int(c-'A') + 10
		}
		return -1
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+1 >= len(s) {
			return "", false
		}
		i++
		switch c := s[i]; c {
		case 'a':
			b.WriteByte(7)
		case 'b':
			b.WriteByte(8)
		case 'e', 'E':
			b.WriteByte(27)
		case 'f':
			b.WriteByte(12)
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'v':
			b.WriteByte(11)
		case '\\', '\'', '"', '?':
			b.WriteByte(c)
		case 'c':
			if i+1 >= len(s) {
				return "", false
			}
			i++
			v := s[i] & 0x1f
			if v == 0 {
				return "", false
			}
			b.WriteByte(v)
		case 'x', 'u', 'U':
			limit := map[byte]int{'x': 2, 'u': 4, 'U': 8}[c]
			v, n := 0, 0
			for n < limit && i+1 < len(s) && hexVal(s[i+1]) >= 0 {
				i++
				v = v*16 + hexVal(s[i])
				n++
			}
			if n == 0 {
				b.WriteByte('\\')
				b.WriteByte(c)
				continue
			}
			if v == 0 {
				return "", false
			}
			if c == 'x' {
				b.WriteByte(byte(v))
			} else {
				b.WriteRune(rune(v))
			}
		default:
			if c >= '0' && c <= '7' {
				v, n := int(c-'0'), 1
				for n < 3 && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '7' {
					i++
					v = v*8 + int(s[i]-'0')
					n++
				}
				if v&0xff == 0 {
					return "", false
				}
				b.WriteByte(byte(v))
				continue
			}
			b.WriteByte('\\')
			b.WriteByte(c)
		}
	}
	return b.String(), true
}

// prependProgram returns a copy of st whose leftmost simple command starts with
// word (the parse tree is shared through the parse cache, so it is never
// changed in place). ok is false when the leftmost command is compound.
func prependProgram(st *syntax.Stmt, word *syntax.Word) (*syntax.Stmt, bool) {
	if st == nil {
		return nil, false
	}
	cp := *st
	switch c := st.Cmd.(type) {
	case *syntax.CallExpr:
		nc := *c
		nc.Args = append([]*syntax.Word{word}, c.Args...)
		cp.Cmd = &nc
		return &cp, true
	case *syntax.BinaryCmd:
		x, ok := prependProgram(c.X, word)
		if !ok {
			return nil, false
		}
		nb := *c
		nb.X = x
		cp.Cmd = &nb
		return &cp, true
	}
	return nil, false
}
