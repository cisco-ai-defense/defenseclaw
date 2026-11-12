// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "strings"

// parseCMD lowers a cmd.exe command line into the neutral IR with a small
// grammar: the operators & && || |, double quotes, ^ escaping, redirections,
// and %VAR% / !VAR! expansions (dynamic unless the name is in a trusted Env).
// A %VAR% whose value is unknown taints the whole statement structure (review
// P2): cmd expands it before parsing, so the token stream is uncertain.
func parseCMD(command string, o Options) *Script {
	s := &Script{Dialect: DialectCMD}
	stmts := splitCMDStatements(command)
	for _, raw := range stmts {
		seg := strings.TrimSpace(raw.text)
		if seg == "" {
			continue
		}
		if cmdHasUnknownExpansion(seg, o) {
			s.Unknowns = append(s.Unknowns, UnknownNode{Reason: ReasonDynamicExpansion, Span: [2]int{raw.start, raw.start + len(raw.text)}})
			continue
		}
		toks := tokenizeCMD(seg)
		c := &Cmd{Span: [2]int{raw.start, raw.start + len(raw.text)}}
		for _, tk := range toks {
			if red, ok := cmdRedir(tk); ok {
				c.Redirs = append(c.Redirs, red)
				continue
			}
			val := stripCMDQuotes(tk.text)
			c.Words = append(c.Words, Word{Value: val, Static: true, Quoted: tk.quoted, Glob: !tk.quoted && looksGlob(val)})
		}
		if len(c.Words) == 0 && len(c.Redirs) == 0 {
			continue
		}
		// cmd /c payload: handled by the extractor via the powershell/-c flags;
		// a leading `call`/`start` is a wrapper handled there too.
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

type cmdTok struct {
	text   string
	quoted bool
}

func tokenizeCMD(seg string) []cmdTok {
	var toks []cmdTok
	var b strings.Builder
	inQ := false
	quoted := false
	flush := func() {
		if b.Len() > 0 {
			toks = append(toks, cmdTok{text: b.String(), quoted: quoted})
			b.Reset()
			quoted = false
		}
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
			quoted = true
			b.WriteByte(ch)
			continue
		}
		if !inQ && (ch == ' ' || ch == '\t') {
			flush()
			continue
		}
		b.WriteByte(ch)
	}
	flush()
	return toks
}

func cmdRedir(tk cmdTok) (Redir, bool) {
	t := tk.text
	if tk.quoted {
		return Redir{}, false
	}
	switch {
	case strings.HasPrefix(t, ">>"):
		return Redir{Op: RedirAppend, Target: Word{Value: strings.TrimSpace(t[2:]), Static: true}}, len(t) > 2
	case strings.HasPrefix(t, ">"):
		return Redir{Op: RedirWrite, Target: Word{Value: strings.TrimSpace(t[1:]), Static: true}}, len(t) > 1
	case strings.HasPrefix(t, "<"):
		return Redir{Op: RedirRead, Target: Word{Value: strings.TrimSpace(t[1:]), Static: true}}, len(t) > 1
	}
	return Redir{}, false
}

func stripCMDQuotes(t string) string {
	t = strings.ReplaceAll(t, `^`, "")
	return strings.ReplaceAll(t, `"`, "")
}

// cmdHasUnknownExpansion reports a %VAR% / !VAR! whose value is not trusted.
func cmdHasUnknownExpansion(seg string, o Options) bool {
	return hasUnknownDelim(seg, '%', o) || hasUnknownDelim(seg, '!', o)
}

func hasUnknownDelim(seg string, d byte, o Options) bool {
	for i := 0; i < len(seg); i++ {
		if seg[i] != d {
			continue
		}
		j := strings.IndexByte(seg[i+1:], d)
		if j < 0 {
			continue
		}
		name := seg[i+1 : i+1+j]
		if name == "" { // %% is a literal %
			i = i + 1 + j
			continue
		}
		if o.Env != nil {
			if _, ok := o.Env[name]; ok {
				i = i + 1 + j
				continue
			}
		}
		return true
	}
	return false
}
