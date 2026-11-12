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
	for _, raw := range splitCMDStatements(command) {
		seg := strings.TrimSpace(raw.text)
		if seg == "" {
			continue
		}
		c := &Cmd{Span: [2]int{raw.start, raw.start + len(raw.text)}}
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
		s.Stmts = append(s.Stmts, &Stmt{Cmds: []*Cmd{c}, Op: raw.op, Cond: raw.op == OpAnd || raw.op == OpOr, Span: c.Span})
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
		if ch == '^' && i+1 < len(command) {
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
		if ch == '^' && i+1 < len(seg) {
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
	for i := 0; i < len(tok); i++ {
		ch := tok[i]
		if ch == '^' && i+1 < len(tok) {
			i++
			lit.WriteByte(tok[i])
			continue
		}
		if ch == '"' {
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
