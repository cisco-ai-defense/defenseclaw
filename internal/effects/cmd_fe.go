// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "strings"

// parseCMD lowers a cmd.exe command line into the neutral IR: the operators
// & && || |, double quotes, ^ escaping, redirections (spaced or attached), and
// %VAR% / !VAR! expansions as word segments the walker resolves (an unknown
// value makes the word dynamic; a trusted one is substituted -- review CM-2).
// Wildcards are globs even when quoted (resolveWord handles the Windows rule --
// review CM-3).
func parseCMD(command string, o Options) *Script {
	s := &Script{Dialect: DialectCMD}
	prevOp := OpNone
	var groups cmdGroups
	for _, raw := range splitCMDStatements(command) {
		op := raw.op
		seg := strings.TrimSpace(raw.text)
		if seg == "" {
			prevOp = op
			continue
		}
		// Cond and PipeIn describe how THIS segment is reached, i.e. the
		// operator that preceded it (review N14/N8).
		cond := prevOp == OpAnd || prevOp == OpOr
		pipeIn := prevOp == OpPipe
		link := OpNone
		if cond {
			link = prevOp // the status of the previous segment gates this one (round 8 F)
		}
		prevOp = op
		// ( ) groups and the if / else / for prefixes: the commands inside run
		// (under a condition for if/else/for); the grouping punctuation is not
		// part of any word (round 8, K29/Y09).
		var segCond, segUnknown bool
		seg, segCond, segUnknown = groups.prepare(seg)
		if segUnknown {
			s.Unknowns = append(s.Unknowns, UnknownNode{Reason: ReasonUnparsedConstruct})
		}
		cond = cond || segCond
		if seg == "" {
			continue
		}
		c := &Cmd{PipeIn: pipeIn, Cond: cond, Span: [2]int{raw.start, raw.start + len(raw.text)}}
		for _, it := range tokenizeCMD(seg) {
			if it.redir != "" {
				red := Redir{FD: it.fd, Target: cmdWord(it.text)}
				switch it.redir {
				case ">":
					red.Op = RedirWrite
					if red.FD < 0 {
						red.FD = 1
					}
				case ">>":
					red.Op = RedirAppend
					if red.FD < 0 {
						red.FD = 1
					}
				case "<":
					red.Op = RedirRead
				}
				c.Redirs = append(c.Redirs, red)
				continue
			}
			c.Words = append(c.Words, cmdWord(it.text))
		}
		if len(c.Words) == 0 && len(c.Redirs) == 0 {
			continue
		}
		s.Stmts = append(s.Stmts, &Stmt{Cmds: []*Cmd{c}, Op: op, Cond: cond, Link: link, Span: c.Span})
	}
	return s
}

type cmdSeg struct {
	text  string
	start int
	op    Op
}

func splitCMDStatements(command string) []cmdSeg {
	var segs []cmdSeg
	var b strings.Builder
	start := 0
	inQ := false
	flush := func(end int, op Op) {
		segs = append(segs, cmdSeg{text: b.String(), start: start, op: op})
		b.Reset()
		start = end
	}
	for i := 0; i < len(command); i++ {
		ch := command[i]
		if ch == 0x5e && !inQ && i+1 < len(command) {
			b.WriteByte(ch)
			i++
			b.WriteByte(command[i])
			continue
		}
		if ch == '"' {
			inQ = !inQ
			b.WriteByte(ch)
			continue
		}
		if !inQ {
			// `>&`/`<&` is a stream dup (e.g. 2>&1), not a statement separator.
			if ch == '&' && b.Len() > 0 {
				if last := b.String()[b.Len()-1]; last == '>' || last == '<' {
					b.WriteByte(ch)
					continue
				}
			}
			if ch == '&' && i+1 < len(command) && command[i+1] == '&' {
				flush(i+2, OpAnd)
				i++
				continue
			}
			if ch == '|' && i+1 < len(command) && command[i+1] == '|' {
				flush(i+2, OpOr)
				i++
				continue
			}
			if ch == '&' {
				flush(i+1, OpSeq)
				continue
			}
			if ch == '|' {
				flush(i+1, OpPipe)
				continue
			}
		}
		b.WriteByte(ch)
	}
	segs = append(segs, cmdSeg{text: b.String(), start: start})
	return segs
}

// cmdItem is one token: a word, or a redirection operator with its fd and the
// target text that follows it.
type cmdItem struct {
	text  string
	redir string // "", ">", ">>", "<"
	fd    int
}

// tokenizeCMD splits a statement into words and redirections, honouring quotes
// and ^ escaping, and splitting a redirection operator whether or not a space
// surrounds it (review CM-1, CM-5).
func tokenizeCMD(seg string) []cmdItem {
	var items []cmdItem
	var b strings.Builder
	inQ := false
	flushWord := func() {
		if b.Len() > 0 {
			items = append(items, cmdItem{text: b.String()})
			b.Reset()
		}
	}
	pendingRedir := ""
	pendingFD := -1
	setRedir := func(op string, fd int) {
		pendingRedir, pendingFD = op, fd
	}
	flushWordWithRedir := func() {
		if pendingRedir != "" {
			if b.Len() == 0 {
				return // target not read yet (whitespace right after the operator)
			}
			items = append(items, cmdItem{text: b.String(), redir: pendingRedir, fd: pendingFD})
			b.Reset()
			pendingRedir, pendingFD = "", -1
			return
		}
		flushWord()
	}
	for i := 0; i < len(seg); i++ {
		ch := seg[i]
		if ch == 0x5e && !inQ && i+1 < len(seg) {
			i++
			b.WriteByte(seg[i])
			continue
		}
		if ch == '"' {
			inQ = !inQ
			b.WriteByte(ch)
			continue
		}
		if !inQ {
			if ch == ' ' || ch == '\t' {
				flushWordWithRedir()
				continue
			}
			if ch == '>' {
				// A stream dup `>&`/`N>&M` (e.g. 2>&1) is not a file redirect:
				// consume &digits and emit nothing (review N15).
				if i+1 < len(seg) && seg[i+1] == '&' {
					if b.Len() <= 1 {
						b.Reset()
					} else {
						flushWordWithRedir()
					}
					i += 2
					for i < len(seg) && seg[i] >= '0' && seg[i] <= '9' {
						i++
					}
					i--
					continue
				}
				// optional preceding fd digit already in b (e.g. 2>)
				fd := -1
				if b.Len() == 1 && b.String()[0] >= '0' && b.String()[0] <= '9' {
					fd = int(b.String()[0] - '0')
					b.Reset()
				} else {
					flushWordWithRedir()
				}
				op := ">"
				if i+1 < len(seg) && seg[i+1] == '>' {
					op = ">>"
					i++
				}
				setRedir(op, fd)
				continue
			}
			if ch == '<' {
				flushWordWithRedir()
				setRedir("<", -1)
				continue
			}
		}
		b.WriteByte(ch)
	}
	flushWordWithRedir()
	return items
}

// cmdWord builds a Word from a cmd token: strips quotes and ^ escapes and
// splits %VAR% / !VAR! into segments for the walker to resolve.
func cmdWord(tok string) Word {
	segs := cmdSegs(tok)
	w := Word{Segs: segs, Quoted: strings.Contains(tok, `"`)}
	hasVar := false
	var b strings.Builder
	for _, s := range segs {
		if s.Var != "" {
			hasVar = true
		} else {
			b.WriteString(s.Lit)
		}
	}
	if !hasVar {
		w.Static = true
		w.Value = b.String()
	}
	return w
}

// cmdSegs splits a cmd token into literal and %VAR% / !VAR! segments, removing
// quotes and ^ escapes. cmd expands %VAR% even inside quotes, so expansion is
// detected regardless of quote state. The per-segment Quoted flag is left false
// because Windows globbing ignores quoting (resolveWord applies that rule).
func cmdSegs(tok string) []WordSeg {
	var segs []WordSeg
	var lit strings.Builder
	flushLit := func() {
		if lit.Len() > 0 {
			segs = append(segs, WordSeg{Lit: lit.String()})
			lit.Reset()
		}
	}
	inQ := false
	for i := 0; i < len(tok); i++ {
		ch := tok[i]
		if ch == '^' && !inQ && i+1 < len(tok) {
			i++
			lit.WriteByte(tok[i])
			continue
		}
		if ch == '"' {
			inQ = !inQ
			continue
		}
		if ch == '%' || ch == '!' {
			end := strings.IndexByte(tok[i+1:], ch)
			if end > 0 {
				flushLit()
				segs = append(segs, WordSeg{Var: tok[i+1 : i+1+end]})
				i = i + 1 + end
				continue
			}
			if end == 0 { // %% or !! -> literal single char
				lit.WriteByte(ch)
				i++
				continue
			}
		}
		lit.WriteByte(ch)
	}
	flushLit()
	if len(segs) == 0 {
		segs = []WordSeg{{Lit: ""}}
	}
	return segs
}

// cmdGroups tracks the open ( ) groups of a cmd line: each entry says whether
// the group is the body of an if / else / for (its commands run on some paths).
type cmdGroups struct{ stack []bool }

func (g *cmdGroups) anyCond() bool {
	for _, c := range g.stack {
		if c {
			return true
		}
	}
	return false
}

// hasCmdKeyword reports a leading keyword (case-insensitive) followed by space,
// "(" or the end of the text.
func hasCmdKeyword(s, kw string) bool {
	if len(s) < len(kw) || !strings.EqualFold(s[:len(kw)], kw) {
		return false
	}
	return len(s) == len(kw) || s[len(kw)] == ' ' || s[len(kw)] == '\t' || s[len(kw)] == '('
}

// prepare strips the grouping punctuation and the if / else / for prefixes from
// one cmd segment and reports whether the rest runs conditionally. unknown is
// set when a prefix could not be parsed (the statement is dropped, and the
// script is not fully known) or when it is a for loop (its variables are not
// modeled).
func (g *cmdGroups) prepare(seg string) (rest string, cond, unknown bool) {
	rest = strings.TrimSpace(seg)
	pending := false
loop:
	for iter := 0; iter < 32; iter++ {
		rest = strings.TrimSpace(rest)
		switch {
		case strings.HasPrefix(rest, "("):
			g.stack = append(g.stack, pending)
			pending = false
			rest = rest[1:]
		case strings.HasPrefix(rest, ")") && len(g.stack) > 0:
			g.stack = g.stack[:len(g.stack)-1]
			rest = rest[1:]
		case hasCmdKeyword(rest, "else"):
			rest = rest[4:]
			pending = true
		case hasCmdKeyword(rest, "if"):
			r, ok := stripCmdIfCondition(rest[2:])
			if !ok {
				return "", true, true
			}
			rest = r
			pending = true
		case hasCmdKeyword(rest, "for"):
			low := strings.ToLower(rest)
			i := strings.Index(low, " do ")
			if i < 0 {
				return "", true, true
			}
			rest = rest[i+4:]
			pending = true
			unknown = true
		default:
			break loop
		}
	}
	cond = pending || g.anyCond()
	for len(g.stack) > 0 && strings.HasSuffix(rest, ")") {
		rest = strings.TrimSpace(rest[:len(rest)-1])
		g.stack = g.stack[:len(g.stack)-1]
	}
	return rest, cond, unknown
}

// stripCmdIfCondition removes the condition of a cmd `if` (after the keyword)
// and returns the command that follows it.
func stripCmdIfCondition(s string) (string, bool) {
	toks := func(s string, n int) ([]string, string) {
		var out []string
		s = strings.TrimSpace(s)
		for len(out) < n && s != "" {
			inQ := false
			end := len(s)
			for i := 0; i < len(s); i++ {
				if s[i] == '"' {
					inQ = !inQ
				}
				if !inQ && (s[i] == ' ' || s[i] == '\t') {
					end = i
					break
				}
			}
			out = append(out, s[:end])
			s = strings.TrimSpace(s[end:])
		}
		return out, s
	}
	s = strings.TrimSpace(s)
	for {
		t, r := toks(s, 1)
		if len(t) == 1 && (strings.EqualFold(t[0], "/i") || strings.EqualFold(t[0], "not")) {
			s = r
			continue
		}
		break
	}
	t, _ := toks(s, 1)
	if len(t) == 0 {
		return "", false
	}
	switch strings.ToLower(t[0]) {
	case "exist", "defined", "errorlevel", "cmdextversion":
		_, r := toks(s, 2)
		return r, true
	}
	if strings.Contains(t[0], "==") {
		_, r := toks(s, 1)
		if strings.HasSuffix(t[0], "==") || strings.HasPrefix(t[0], "==") {
			// "a ==b" / "a== b": the other operand is the next token.
			_, r = toks(s, 2)
		}
		return r, true
	}
	t3, r3 := toks(s, 3)
	if len(t3) == 3 {
		switch strings.ToLower(t3[1]) {
		case "==", "equ", "neq", "lss", "leq", "gtr", "geq":
			return r3, true
		}
	}
	return "", false
}
