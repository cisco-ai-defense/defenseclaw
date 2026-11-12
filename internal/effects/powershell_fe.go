// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "strings"

// parsePowerShell is an interim, conservative PowerShell frontend. It lowers
// the clearly-static forms (simple pipelines of cmdlet calls with -Param value
// and positional arguments, single/double-quoted strings) into the neutral IR
// and marks anything it cannot place statically -- script blocks {...},
// subexpressions $(...), variable-as-command (& $x), member access, here-
// strings with expansion -- as an UnknownNode. When the full-grammar parser in
// internal/psparse lands (lane s7-pwsh), its adapter replaces this file at the
// IR seam; the extractor and program table are unchanged. It never bridges onto
// actionfacts and never claims "known" for a dynamic construct.
func parsePowerShell(command string, o Options) *Script {
	s := &Script{Dialect: DialectPowerShell}
	for _, stmtText := range splitPSStatements(command) {
		seg := strings.TrimSpace(stmtText)
		if seg == "" {
			continue
		}
		if psHasOpaqueConstruct(seg) {
			s.Unknowns = append(s.Unknowns, UnknownNode{Reason: ReasonUnparsedConstruct})
			continue
		}
		for pi, stage := range strings.Split(seg, "|") {
			stage = strings.TrimSpace(stage)
			if stage == "" {
				continue
			}
			toks := tokenizePS(stage)
			if len(toks) == 0 {
				continue
			}
			c := &Cmd{PipeIn: pi > 0}
			for _, tk := range toks {
				val, static, quoted := psTokenValue(tk, o)
				c.Words = append(c.Words, Word{Value: val, Static: static, Quoted: quoted,
					Glob: static && !quoted && looksGlob(val), Reason: psReason(static)})
			}
			s.Stmts = append(s.Stmts, &Stmt{Cmds: []*Cmd{c}})
		}
	}
	return s
}

func psReason(static bool) ReasonCode {
	if static {
		return ""
	}
	return ReasonDynamicExpansion
}

func splitPSStatements(command string) []string {
	var out []string
	var b strings.Builder
	depth := 0
	inS, inD := false, false
	for i := 0; i < len(command); i++ {
		ch := command[i]
		switch {
		case ch == '\'' && !inD:
			inS = !inS
		case ch == '"' && !inS:
			inD = !inD
		case (ch == '{' || ch == '(') && !inS && !inD:
			depth++
		case (ch == '}' || ch == ')') && !inS && !inD:
			if depth > 0 {
				depth--
			}
		case (ch == ';' || ch == '\n') && depth == 0 && !inS && !inD:
			out = append(out, b.String())
			b.Reset()
			continue
		}
		b.WriteByte(ch)
	}
	out = append(out, b.String())
	return out
}

func psHasOpaqueConstruct(seg string) bool {
	// Script blocks, subexpressions and invocation of a dynamic command are not
	// statically placeable here.
	if strings.Contains(seg, "$(") || strings.Contains(seg, "@(") || strings.Contains(seg, "{") {
		return true
	}
	trimmed := strings.TrimSpace(seg)
	if strings.HasPrefix(trimmed, "&") || strings.HasPrefix(trimmed, ".") {
		// & $cmd / . $script: dynamic invocation.
		rest := strings.TrimSpace(trimmed[1:])
		if strings.HasPrefix(rest, "$") || strings.HasPrefix(rest, "{") {
			return true
		}
	}
	return false
}

func tokenizePS(stage string) []string {
	var toks []string
	var b strings.Builder
	inS, inD := false, false
	flush := func() {
		if b.Len() > 0 {
			toks = append(toks, b.String())
			b.Reset()
		}
	}
	for i := 0; i < len(stage); i++ {
		ch := stage[i]
		switch {
		case ch == '\'' && !inD:
			inS = !inS
			b.WriteByte(ch)
		case ch == '"' && !inS:
			inD = !inD
			b.WriteByte(ch)
		case (ch == ' ' || ch == '\t') && !inS && !inD:
			flush()
		default:
			b.WriteByte(ch)
		}
	}
	flush()
	return toks
}

// psTokenValue returns the static value of a PowerShell token. A single-quoted
// string is verbatim; a double-quoted string with a $ is expandable (dynamic);
// a bare $var or $env: is dynamic unless the name is a trusted Env value.
func psTokenValue(tk string, o Options) (string, bool, bool) {
	if len(tk) >= 2 && tk[0] == '\'' && tk[len(tk)-1] == '\'' {
		return tk[1 : len(tk)-1], true, true
	}
	if len(tk) >= 2 && tk[0] == '"' && tk[len(tk)-1] == '"' {
		inner := tk[1 : len(tk)-1]
		if strings.Contains(inner, "$") {
			return "", false, true
		}
		return inner, true, true
	}
	if strings.HasPrefix(tk, "$env:") {
		name := tk[len("$env:"):]
		if o.Env != nil {
			if v, ok := o.Env[name]; ok {
				return v, true, false
			}
		}
		return "", false, false
	}
	if strings.HasPrefix(tk, "$") {
		if o.Env != nil {
			if v, ok := o.Env[strings.TrimPrefix(tk, "$")]; ok {
				return v, true, false
			}
		}
		return "", false, false
	}
	return tk, true, false
}
