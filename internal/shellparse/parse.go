// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package shellparse provides the full shell parser shared by hook command
// proofs and per-command policy evaluation.
package shellparse

import (
	"errors"
	"io"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Reader is the reader to hand a recursive shell parser
// (syntax.Parser.Parse) for command: a command past the reading budget
// (BudgetExceeded) reads as an error, so the parser returns that error
// instead of recursing into it. Every hook-path and gateway reader parses
// through it, so no caller has to remember the bound (GAP-2556: the hook
// client tilde twin parsed the raw command before any bound and overflowed
// the 1 GB stack).
func Reader(command string) io.Reader {
	if TooDeep(command) {
		return tooDeepReader{}
	}
	return strings.NewReader(command)
}

// ErrTooDeep is the read error of a command past the reading budget.
var ErrTooDeep = errors.New("shellparse: command is past the reading budget")

type tooDeepReader struct{}

func (tooDeepReader) Read([]byte) (int, error) { return 0, ErrTooDeep }

// Parse reads a command with the same Bash-then-POSIX grammar used for hook
// command proofs. A command past the reading budget (BudgetExceeded) is not
// parsed.
func Parse(command string) (*syntax.File, bool) {
	return parse(command, false)
}

// ParseWithComments is Parse with the comments kept in the tree, for a
// reader that must know which bytes the shell skips as a comment.
func ParseWithComments(command string) (*syntax.File, bool) {
	return parse(command, true)
}

func parse(command string, comments bool) (*syntax.File, bool) {
	if len(command) < largeCommandMin || len(command) > largeCommandMax {
		return parseCommand(command, comments)
	}
	key := parseCacheKey{command, comments}
	if file, ok, hit := cachedParse(key); hit {
		return file, ok
	}
	file, ok := parseCommand(command, comments)
	storeParse(key, file, ok)
	return file, ok
}

func parseCommand(command string, comments bool) (*syntax.File, bool) {
	if TooDeep(command) {
		return nil, false
	}
	for _, variant := range []syntax.LangVariant{syntax.LangBash, syntax.LangPOSIX} {
		file, err := syntax.NewParser(syntax.Variant(variant), syntax.KeepComments(comments)).Parse(Reader(command), "")
		if err == nil {
			return file, true
		}
	}
	return nil, false
}
