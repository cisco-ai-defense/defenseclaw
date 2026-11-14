// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import (
	"errors"

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
// The recovering mode of mvdan.cc/sh (v3.13.1, and still v3.14.1) can index
// past the current word: after it recovers an error inside an assignment's
// $(( arithmetic, the '=' offset of the assignment word is left set for the
// next, shorter word, and Parser.hasValidIdent / getAssign slice with it
// (rel-1-0-10:GAP-0437). An agent chooses the command text, so that fault
// must not escape into the readers: it is contained here, reported as
// ErrParserFault with no tree, and marked on trunc as a reading that stopped
// in the parse (bounded.Nodes). A caller decides such a command as one whose
// effects it cannot read (the proof bound, the pack's unknown tier), never by
// the fault. trunc may be nil.
func ParseRecovering(command string, maxErrors int, trunc *bounded.Truncated) (*syntax.File, error) {
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
