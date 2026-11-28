// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package shellparse provides the full shell parser shared by hook command
// proofs and per-command policy evaluation.
package shellparse

import (
	"errors"
	"io"
	"strings"
	"sync"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/workcount"
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
	if len(command) < largeCommandMin || len(command) > MaxCommandBytes {
		return parseCommand(command, comments)
	}
	key := parseCacheKey{command, comments}
	if file, ok, _, hit := cachedParse(key); hit {
		return file, ok
	}
	file, ok, bash := parseCommandVariant(command, comments)
	storeParse(key, file, ok, bash)
	return file, ok
}

func parseCommand(command string, comments bool) (*syntax.File, bool) {
	file, ok, _ := parseCommandVariant(command, comments)
	return file, ok
}

// parseCommandVariant is parseCommand that also tells whether the Bash
// grammar read the tree (bash false: the POSIX one did, or neither).
func parseCommandVariant(command string, comments bool) (file *syntax.File, ok, bash bool) {
	// The budget's second stage may already have parsed the text, in the
	// same grammars and order and with no comments kept: that tree is this
	// parse's answer, handed over once (budgetExceeded), with the grammar
	// that read it. An 8 KB call otherwise parsed the same text twice in a
	// row (substrate-1 GAP-1153).
	reason, measured, measuredBash := budgetExceeded(command, !comments)
	if reason != "" {
		return nil, false, false
	}
	if measured != nil {
		return measured, true, measuredBash
	}
	for at, variant := range parseVariants {
		workcount.AddLarge(workcount.LargeParse, len(command))
		file, err := parseWith(at, comments, command)
		if err == nil {
			return file, true, variant == syntax.LangBash
		}
	}
	return nil, false, false
}

// ParseBash reads command in the Bash grammar alone, without comments: the
// tree syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse gives, and
// false where that parse fails. A large command is answered from the tree
// Parse keeps (parse cache): that parse tries Bash first, so a tree Bash
// read is this tree. Readers that each parsed a large command again on their
// own cost the 1 MiB here-document a full parse apiece, three of them per
// call (rel-1-0-10:GAP-0299). Where Bash did not read the kept tree, the
// command is parsed here as before.
func ParseBash(command string) (*syntax.File, bool) {
	if len(command) >= largeCommandMin && len(command) <= MaxCommandBytes {
		key := parseCacheKey{command, false}
		file, ok, bash, hit := cachedParse(key)
		if !hit {
			file, ok, bash = parseCommandVariant(command, false)
			storeParse(key, file, ok, bash)
		}
		if ok && bash {
			return file, true
		}
	}
	workcount.AddLarge(workcount.LargeParse, len(command))
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	return file, err == nil
}

// parseVariants are the grammars Parse tries, in order.
var parseVariants = [...]syntax.LangVariant{syntax.LangBash, syntax.LangPOSIX}

// parserPools keeps a parser of each grammar, with and without comments, for
// the next parse: syntax.NewParser allocates two 1 KB buffers a parse, about
// a fifth of the memory a sandbox hook took on a compound call (substrate-1
// GAP-0923). A parser is reused only once it is done working, as
// syntax.Parser.Parse allows: Parse resets its state and allocates every
// node of the new tree anew, so a tree never shares a node with another.
var parserPools [len(parseVariants)][2]sync.Pool

func init() {
	for at, variant := range parseVariants {
		for kept, comments := range []bool{false, true} {
			parserPools[at][kept].New = func() any {
				return syntax.NewParser(syntax.Variant(variant), syntax.KeepComments(comments))
			}
		}
	}
}

// parseWith parses command in parseVariants[at] with a pooled parser. A
// parser whose parse panicked is not reused.
func parseWith(at int, comments bool, command string) (*syntax.File, error) {
	kept := 0
	if comments {
		kept = 1
	}
	pool := &parserPools[at][kept]
	parser := pool.Get().(*syntax.Parser)
	done := false
	file, err := containParse(nil, func() (*syntax.File, error) {
		file, err := parser.Parse(Reader(command), "")
		done = true
		return file, err
	})
	if done {
		pool.Put(parser)
	}
	return file, err
}
