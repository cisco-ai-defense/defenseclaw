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

// MaxChainOperators bounds the chain operators of a command: the | and the
// && of its parse tree (|| counts as one). The parser builds one nested node
// for each, left-deep, and every recursive reader of the tree (the parse
// cache copy, syntax.Walk, the analysers) recurses once per node: a 500 KB
// list of || overflowed the stack of the gateway in the copy of the parse
// cache, a fatal error no recover catches (GAP-0255), and a 67 KB pipeline
// held 6 GiB in the scope names of the statement split (GAP-0254). 3.1
// million real agent calls (owner traces, Claude Code and Codex, Linux,
// macOS, Windows) carry at most 36 of these in their tree (p99.99: 10), so
// the bound is more than 100 times the largest real call.
const MaxChainOperators = 4096

// MaxChainOperatorBytes bounds the | and && bytes of a command text,
// counted in the one linear pass over every byte (|| counts twice, and
// quotes and here-document bodies count too, so the count never
// under-counts). A text with no more than MaxChainOperators of them cannot
// be past the bound of its tree and is not parsed to find out. A text with
// more is measured on its tree (a here-document of shell code or prose has
// thousands of | bytes and no chain), unless it has more than
// MaxChainOperatorBytes, which is refused unparsed: parsing a chain costs
// about 2 KB of memory for each byte, so this keeps the measure itself to
// about 130 MB.
const MaxChainOperatorBytes = 1 << 15

// MaxParsedNodes bounds the nodes of a parsed command of largeCommandMin
// bytes or more (a smaller command cannot reach it: a node takes at least
// two bytes in four). It budgets the words, statements and every other
// node of a flat command the way MaxChainOperators budgets a chain: the
// largest real call has 13,559 nodes (p99.99: 375), so the bound is 19
// times that. A command past it reads as unparseable, which the hook
// handles as past the reading bounds (BudgetExceeded).
const MaxParsedNodes = 1 << 18

// Budget reasons BudgetExceeded returns.
const (
	BudgetNesting = "nesting"
	BudgetBraces  = "brace_expansion"
	BudgetChain   = "chain_operators"
	BudgetNodes   = "parsed_nodes"
)

// TooDeep reports whether command is past the reading bounds: it nests (, {
// or [ deeper than MaxNestingDepth, has more than MaxChainOperators chain
// operators (both counted in one linear pass over every byte, quotes and
// escapes too, so the bound holds whatever the grammar), or its brace
// expansions would produce more than MaxBraceFields words or MaxBraceBytes
// bytes (BraceExpansionTooLarge, GAP-0187). Callers take their over-limit
// path and never hand such a command to a recursive parser or an expander.
func TooDeep(command string) bool {
	return tooDeepReason(command) != ""
}

// tooDeepReason is the reason command is past the reading bounds, or "".
// The answer for a command that is large, or that needed its tree measured,
// is remembered for the next ask: the proofs of one hook call ask it for
// the same text on every parse and every reader.
func tooDeepReason(command string) string {
	if len(command) >= largeCommandMin && len(command) <= largeCommandMax || len(command) > MaxChainOperators {
		return tooDeepRemembered(command)
	}
	reason, _ := tooDeepScan(command)
	return reason
}

// tooDeepScan is the one linear pass. chainBytes is true when the text has
// more | and && bytes than MaxChainOperators and no more than
// MaxChainOperatorBytes: its tree must be measured (chainTreeOver).
func tooDeepScan(command string) (reason string, chainBytes bool) {
	depth, chain, braces := 0, 0, false
	for i := 0; i < len(command); i++ {
		switch command[i] {
		case '(', '{', '[':
			if depth++; depth > MaxNestingDepth {
				return BudgetNesting, false
			}
			braces = braces || command[i] == '{'
		case ')', '}', ']':
			if depth > 0 {
				depth--
			}
		case '|':
			chain++
		case '&':
			if i+1 < len(command) && command[i+1] == '&' {
				chain++
				i++
			}
		}
	}
	if braces && BraceExpansionTooLarge(command) {
		return BudgetBraces, false
	}
	if chain > MaxChainOperatorBytes {
		return BudgetChain, false
	}
	return "", chain > MaxChainOperators
}

// chainTreeOver reports whether the parse tree of command has more than
// MaxChainOperators chain nodes. The parse itself is bounded (the text has
// at most MaxChainOperatorBytes | and && bytes and passed the nesting
// bound), and the walk recurses once per chain node of that tree.
func chainTreeOver(command string) bool {
	for _, variant := range []syntax.LangVariant{syntax.LangBash, syntax.LangPOSIX} {
		file, err := syntax.NewParser(syntax.Variant(variant)).Parse(strings.NewReader(command), "")
		if err != nil {
			continue
		}
		chain := 0
		syntax.Walk(file, func(node syntax.Node) bool {
			if binary, ok := node.(*syntax.BinaryCmd); ok {
				switch binary.Op {
				case syntax.Pipe, syntax.PipeAll, syntax.AndStmt, syntax.OrStmt:
					chain++
				}
			}
			return chain <= MaxChainOperators
		})
		return chain > MaxChainOperators
	}
	return false
}

// BudgetExceeded returns the reason command is past the reading budget
// (TooDeep, or MaxParsedNodes for a large command), or "" when it is within
// it. A call past it is read as opaque: the hook judges it as past the
// evaluation limit, with the reason parse_budget_exceeded.
func BudgetExceeded(command string) string {
	if reason := tooDeepReason(command); reason != "" {
		return reason
	}
	if len(command) >= largeCommandMin {
		if _, _, over := parseChecked(command, false); over {
			return BudgetNodes
		}
	}
	return ""
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
// the reading budget (BudgetExceeded) is not parsed.
func Parse(command string) (*syntax.File, bool) {
	file, ok, _ := parseChecked(command, false)
	return file, ok
}

// ParseWithComments is Parse with the comments kept in the tree, for a
// reader that must know which bytes the shell skips as a comment.
func ParseWithComments(command string) (*syntax.File, bool) {
	file, ok, _ := parseChecked(command, true)
	return file, ok
}

// parseChecked is Parse that also reports whether the command parsed but
// has more than MaxParsedNodes nodes.
func parseChecked(command string, comments bool) (file *syntax.File, ok, over bool) {
	if len(command) < largeCommandMin || len(command) > largeCommandMax {
		return parseCommand(command, comments)
	}
	key := parseCacheKey{command, comments}
	if file, ok, over, hit := cachedParse(key); hit {
		return file, ok, over
	}
	file, ok, over = parseCommand(command, comments)
	storeParse(key, file, ok, over)
	return file, ok, over
}

func parseCommand(command string, comments bool) (file *syntax.File, ok, over bool) {
	if TooDeep(command) {
		return nil, false, false
	}
	for _, variant := range []syntax.LangVariant{syntax.LangBash, syntax.LangPOSIX} {
		file, err := syntax.NewParser(syntax.Variant(variant), syntax.KeepComments(comments)).Parse(Reader(command), "")
		if err == nil {
			if len(command) >= largeCommandMin && !withinParsedNodes(file) {
				return nil, false, true
			}
			return file, true, false
		}
	}
	return nil, false, false
}

// withinParsedNodes reports whether file has at most MaxParsedNodes nodes.
// The walk recurses once per nesting level and per chain operator, both
// bounded by TooDeep, and stops descending once it is past the bound.
func withinParsedNodes(file *syntax.File) bool {
	nodes := 0
	syntax.Walk(file, func(node syntax.Node) bool {
		if node == nil {
			return false
		}
		nodes++
		return nodes <= MaxParsedNodes
	})
	return nodes <= MaxParsedNodes
}
