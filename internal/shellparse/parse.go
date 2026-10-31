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

// MaxNestingDepth bounds how deep a command may nest (, { and [ before a
// parser reads it. The mvdan parser recurses once or more per level of (,
// $(, $((, { and [, and a 180 KiB command of ( overflowed the 1 GB
// goroutine stack of the Windows gateway: a fatal error no recover catches,
// so the whole gateway exited (GAP-2537). No real command nests this deep.
const MaxNestingDepth = 512

// TooDeep reports whether command nests (, { or [ deeper than
// MaxNestingDepth, in one linear pass over every byte (quotes and escapes
// count too, so the bound holds whatever the grammar). A command it reports
// is past the reading bounds: callers take their over-limit path and never
// hand it to a recursive parser.
func TooDeep(command string) bool {
	depth := 0
	for i := 0; i < len(command); i++ {
		switch command[i] {
		case '(', '{', '[':
			if depth++; depth > MaxNestingDepth {
				return true
			}
		case ')', '}', ']':
			if depth > 0 {
				depth--
			}
		}
	}
	return false
}

// Reader is the reader to hand a recursive shell parser
// (syntax.Parser.Parse) for command: a command past MaxNestingDepth reads
// as an error, so the parser returns that error instead of recursing into
// it. Every hook-path and gateway reader parses through it, so no caller
// has to remember the bound (GAP-2556: the hook client tilde twin parsed
// the raw command before any bound and overflowed the 1 GB stack).
func Reader(command string) io.Reader {
	if TooDeep(command) {
		return tooDeepReader{}
	}
	return strings.NewReader(command)
}

// ErrTooDeep is the read error of a command past MaxNestingDepth.
var ErrTooDeep = errors.New("shellparse: command nests past the reading bound")

type tooDeepReader struct{}

func (tooDeepReader) Read([]byte) (int, error) { return 0, ErrTooDeep }

// Parse reads a command with the same Bash-then-POSIX grammar used for hook
// command proofs. Callers bound their inputs before parsing; a command past
// MaxNestingDepth is not parsed.
func Parse(command string) (*syntax.File, bool) {
	return parse(command, false)
}

// ParseWithComments is Parse with the comments kept in the tree, for a
// reader that must know which bytes the shell skips as a comment.
func ParseWithComments(command string) (*syntax.File, bool) {
	return parse(command, true)
}

func parse(command string, comments bool) (*syntax.File, bool) {
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
