// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import (
	"errors"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"mvdan.cc/sh/v3/syntax"
)

// ErrParserFault is the error of a recovering parse that the shell parser
// could not finish: it failed internally instead of returning a tree or a
// syntax error.
var ErrParserFault = errors.New("shellparse: the recovering shell parser failed internally")

// ParseRecovering parses command with the Bash grammar and the parser's
// error recovery (syntax.RecoverErrors(maxErrors)), so a command with
// syntax errors still yields the calls and redirects the parser could read.
// It is the only recovering parse of hook commands.
//
// The recovering mode of mvdan.cc/sh (v3.13.1, and still v3.14.1) has two
// faults on agent-chosen text. Both are contained here:
//
//   - It can index past the current word: after it recovers an error inside
//     an assignment's $(( arithmetic, the '=' offset of the assignment word
//     is left set for the next, shorter word, and Parser.hasValidIdent /
//     getAssign slice with it (rel-1-0-10:GAP-0437). The panic is recovered.
//   - It can loop forever: its lexer records "invalid UTF-8 encoding" as the
//     parse error but keeps lexing, the recovery resets the token, and the
//     command loop reports the same token again without consuming it, a
//     no-op once an error is recorded (rel-1-0-10:GAP-0487). The loop reads
//     no input and calls nothing of ours, so no reader, context or time
//     bound can stop it once it has started. The bound is therefore on the
//     input: text that is not valid UTF-8 never gets a recovering parse.
//     Hook, inspect and approval text arrives as JSON, which decodes to
//     valid UTF-8 only; other text can come from a reader that cut a string
//     inside a rune.
//
// Either fault is reported as ErrParserFault with no tree, and marked on
// trunc as a reading that stopped in the parse (bounded.Nodes). A caller
// judges such a command as one that could not be parsed safely: a block in
// every pack, never a reading it can bound. trunc may be nil.
func ParseRecovering(command string, maxErrors int, trunc *bounded.Truncated) (*syntax.File, error) {
	if !utf8.ValidString(command) {
		if trunc != nil {
			trunc.Hit(bounded.Nodes)
		}
		return nil, ErrParserFault
	}
	return containParse(trunc, func() (*syntax.File, error) {
		return syntax.NewParser(syntax.Variant(syntax.LangBash), syntax.RecoverErrors(maxErrors)).Parse(Reader(command), "")
	})
}

// containParse runs one parse and turns a parser fault into ErrParserFault.
func containParse(trunc *bounded.Truncated, parse func() (*syntax.File, error)) (file *syntax.File, err error) {
	defer func() {
		if recover() != nil {
			file, err = nil, ErrParserFault
			if trunc != nil {
				trunc.Hit(bounded.Nodes)
			}
		}
	}()
	return parse()
}
