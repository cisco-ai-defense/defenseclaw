// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import (
	"reflect"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"mvdan.cc/sh/v3/syntax"
)

// The reading budget: one set of bounds every shell reader of the hook path
// checks before it runs (Reader, Parse and TooDeep ask BudgetExceeded), so
// no input an agent writes can make a reader recurse, allocate or run past
// them (GAP-0254: a 67 KB pipeline held the hook past 6 GiB; GAP-0255: a
// 499 KB left-deep list overflowed the goroutine stack in the copy of the
// parse cache, a fatal error no recover catches; GAP-0284 and GAP-0285 of
// the review: text that does not parse, and trees that are not chains).
//
// The budget has two stages. The first is one linear pass over the raw
// bytes, independent of the grammar and of whether the text parses: it
// counts the nesting of ( { [ (quotes, escapes and here-document bodies
// count too, so it never under-counts), the | and && bytes, and the words.
// A text past a hard bound is refused unparsed; a text past a soft bound is
// measured on its tree, because ordinary text (a here-document of shell
// code, a patch) has many such bytes and no structure. The second stage
// parses such a text once and counts nodes, depth and chain operators with
// an iterative walk, so the measure itself cannot overflow the stack. A
// text past a soft bound that does not parse as a chain cannot be measured
// and is over the budget.
//
// The values come from two measures. The owner traces (3.13 million real
// calls of Claude Code and Codex on Linux, macOS and Windows) give the
// largest real call: 97,371 bytes, 12,198 words, 38 chain nodes in the tree
// (1,600 | and && bytes in the text), 13,559 nodes, and a p99.99 of 25,175
// bytes, 3,220 words, 10 chain nodes. The cost curve of the hook on every
// tree family (docs/PARSELIMITS.md, TestParseBudgetCostCurve) gives the
// largest size that still answers in about 100 ms and 64 MiB on the slowest
// shape. Each bound is between the two: above the real call by a margin,
// below the point where the cost leaves that envelope.
const (
	// MaxNestingDepth bounds how deep a command may nest (, { and [ before a
	// parser reads it. The mvdan parser recurses once or more per level of
	// (, $(, $((, { and [, and a 180 KiB command of ( overflowed the 1 GB
	// goroutine stack of the Windows gateway (GAP-2537). No real command
	// nests this deep.
	MaxNestingDepth = 512

	// MaxCommandBytes bounds the text of a command at the body of one
	// hook call (1 MiB); the largest real call is 97,371 bytes. It is a
	// bound on the work of the first stage, not on cost: a here-document of
	// ordinary text this large costs the readers a few hundred milliseconds
	// (the curve), and the structural bounds below do the rest.
	MaxCommandBytes = 1 << 20

	// MaxChainOperators bounds the | && and || nodes of the parse tree.
	// The parser builds one nested node for each, left-deep, and every
	// recursive reader recurses once per node. The costliest family (a
	// pipeline of command substitutions) costs 77 ms and 24 MiB at 512 and
	// 250 ms and 80 MiB at 1024; the largest real call has 38.
	MaxChainOperators = 512

	// MaxParsedNodes bounds the nodes of the tree (every node, of every
	// kind). A flat command of 32,768 nodes costs 100 to 165 ms and 67 MiB;
	// the largest real call has 13,559.
	MaxParsedNodes = 32768

	// MaxTreeDepth bounds the nesting of nodes in the tree, which counts
	// the left-deep chains of every kind (arithmetic, lists, pipelines,
	// elif) as well as grouping. The readers recurse once per level; an
	// arithmetic chain of 2,048 additions costs 66 ms and 23 MiB.
	MaxTreeDepth = 2048

	// MaxChainBytes bounds the | and && bytes of the text (|| counts
	// twice). Over it the text is refused unparsed: parsing a chain costs
	// about 2 KB for each such byte, so it also bounds the measure itself
	// to about 32 MiB. The largest real call has 1,600.
	MaxChainBytes = 16384

	// MaxTokens bounds the blank-separated words plus the separator and
	// operator bytes (; & | newline and the arithmetic operators) of the
	// text, outside data (quoted text, comments and here-document bodies are
	// not parsed as commands and not counted). Over it the text is refused
	// unparsed. It bounds the parse of a flat command: 131,072 tokens of
	// statements cost 60 MiB and 40 ms (the curve). The largest real call
	// has about 15,000.
	MaxTokens = 131072

	// softChainBytes and softBytes are the sizes from which a text is
	// measured on its tree. Below both, the text cannot be past
	// MaxChainOperators (a chain node takes a | or & byte), MaxTreeDepth (a
	// level of the tree takes a byte of text) or MaxParsedNodes (a byte
	// makes at most two nodes), so it is not parsed to find out. Real calls
	// past them are about 1 in 300.
	softChainBytes = MaxChainOperators
	softBytes      = MaxTreeDepth
)

// Budget reasons BudgetExceeded returns.
const (
	BudgetNesting  = "nesting"
	BudgetBraces   = "brace_expansion"
	BudgetBytes    = "command_bytes"
	BudgetChain    = "chain_operators"
	BudgetTokens   = "tokens"
	BudgetNodes    = "parsed_nodes"
	BudgetDepth    = "tree_depth"
	BudgetUnparsed = "unparsed_chain"
)

// BudgetTruncated is the bound rule's view of a budget reason
// (BudgetExceeded): the cap kind the reading hit, for the verdict floor of
// internal/guardrail/bounded. The reasons map to the kinds: bytes to Bytes;
// nesting and tree depth to Depth; tree nodes to Nodes; chain operators,
// tokens, brace expansion and an unparsed chain to Items.
func BudgetTruncated(reason string) bounded.Truncated {
	var t bounded.Truncated
	switch reason {
	case "":
	case BudgetBytes:
		t.Hit(bounded.Bytes)
	case BudgetNesting, BudgetDepth:
		t.Hit(bounded.Depth)
	case BudgetNodes:
		t.Hit(bounded.Nodes)
	default:
		t.Hit(bounded.Items)
	}
	return t
}

// TooDeep reports whether command is past the reading budget (see
// BudgetExceeded). Callers take their over-limit path and never hand such a
// command to a recursive parser or an expander.
func TooDeep(command string) bool {
	return BudgetExceeded(command) != ""
}

// BudgetExceeded returns the reason command is past the reading budget, or
// "" when it is within it. The answer for a text of 512 bytes or more is
// remembered for the next ask: the proofs of one hook call ask it for the
// same text on every parse and every reader.
func BudgetExceeded(command string) string {
	if len(command) < budgetMemoMin {
		return computeBudget(command)
	}
	budgetMemo.Lock()
	for _, entry := range budgetMemo.entries {
		if len(entry.command) == len(command) && entry.command == command {
			reason := entry.reason
			budgetMemo.Unlock()
			return reason
		}
	}
	budgetMemo.Unlock()
	reason := computeBudget(command)
	budgetMemo.Lock()
	if len(budgetMemo.entries) >= budgetMemoEntries {
		budgetMemo.entries = append(budgetMemo.entries[:0], budgetMemo.entries[1:]...)
	}
	budgetMemo.entries = append(budgetMemo.entries, budgetMemoEntry{command, reason})
	budgetMemo.Unlock()
	return reason
}

const (
	budgetMemoMin     = 512
	budgetMemoEntries = 8
)

type budgetMemoEntry struct{ command, reason string }

var budgetMemo struct {
	sync.Mutex
	entries []budgetMemoEntry
}

// rawChainBytes and rawTokens are the bounds on the raw counts, which
// include every byte of the text, data and all. The counts of the first
// stage skip what the shell reads as data (below); that is a reading of the
// grammar by this pass, not by the parser, so where the two differ the
// parser is given a text the raw bound has still limited, and the tree
// measure that follows counts what it really holds.
const (
	rawChainBytes = 8 * MaxChainBytes
	rawTokens     = 4 * MaxTokens
)

// budgetCounts are the counts of one pass over the text.
type budgetCounts struct {
	chain, tokens int
	inWord        bool
}

// feed counts the byte at command[i] and returns how many bytes it consumed
// beyond itself.
func (n *budgetCounts) feed(command string, i int) (extra int) {
	c := command[i]
	switch c {
	case '|':
		n.chain++
		n.tokens++
	case '&':
		if i+1 < len(command) && command[i+1] == '&' {
			n.chain++
			extra = 1
		}
		n.tokens++
	default:
		if tokenBytes[c] {
			n.tokens++
		}
	}
	blank := c == ' ' || c == '\t' || c == '\n' || c == '\r' || tokenBytes[c] || c == '|' || c == '&' || c == '(' || c == ')'
	if !blank && !n.inWord {
		n.tokens++
	}
	n.inWord = !blank
	return extra
}

func computeBudget(command string) string {
	if len(command) > MaxCommandBytes {
		return BudgetBytes
	}
	raw, aware, braces, reason := scanCounts(command)
	if reason != "" {
		return reason
	}
	if braces && BraceExpansionTooLarge(command) {
		return BudgetBraces
	}
	switch {
	case aware.chain > MaxChainBytes || raw.chain > rawChainBytes:
		return BudgetChain
	case aware.tokens > MaxTokens || raw.tokens > rawTokens:
		return BudgetTokens
	case aware.chain <= softChainBytes && len(command) <= softBytes:
		return ""
	}
	file, ok := parseUnbudgeted(command)
	if !ok {
		// Text that does not parse has no tree to count. Past the soft
		// chain bound it may be a chain with a syntax error (GAP-0284); other
		// text is bounded by MaxTokens and MaxCommandBytes.
		if aware.chain > softChainBytes {
			return BudgetUnparsed
		}
		return ""
	}
	return measureTree(file)
}

// scanCounts is the one linear pass over the raw bytes: the nesting of ( {
// [ (whose overflow it returns as the reason) and the two counts, raw and
// aware of data.
func scanCounts(command string) (raw, aware budgetCounts, braces bool, reason string) {
	depth := 0
	var pending []heredocSpec
	dataUntil := 0
	for i := 0; i < len(command); i++ {
		c := command[i]
		switch c {
		case '(', '{', '[':
			if depth++; depth > MaxNestingDepth {
				return raw, aware, braces, BudgetNesting
			}
			braces = braces || c == '{'
		case ')', '}', ']':
			if depth > 0 {
				depth--
			}
		}
		if i < dataUntil {
			// Data the shell does not parse: only the raw count sees it.
			raw.feed(command, i)
			aware.inWord = true
			continue
		}
		if end := dataSpan(command, i, &pending); end > i {
			dataUntil = end
			raw.feed(command, i)
			aware.inWord = true
			continue
		}
		if skip := aware.feed(command, i); skip > 0 {
			raw.feed(command, i)
			raw.feed(command, i+skip)
			i += skip
			continue
		}
		raw.feed(command, i)
	}
	return raw, aware, braces, ""
}

// heredocSpec is a here-document whose body starts after the next newline.
type heredocSpec struct {
	delim string
	dash  bool // <<-: leading tabs of the closing line are removed
	plain bool // the delimiter is unquoted: the body expands $( and `
}

// dataSpan returns the end of the data that starts at command[i], or i when
// none does. Data is what the shell never parses as commands: a
// single-quoted string, a comment, and the body of a here-document (unless
// the body is expanded and holds a command substitution). The pass counts a
// | or && in it for the raw bound only, so a here-document of shell code or
// prose is not mistaken for a chain. A here-document marker adds to
// pending; the body is data from the next newline.
func dataSpan(command string, i int, pending *[]heredocSpec) int {
	switch c := command[i]; c {
	case '\\':
		return i + 2 // an escaped byte is never a quote, a # or a <
	case '\'':
		if i > 0 && command[i-1] == '$' {
			for j := i + 1; j < len(command); j++ {
				switch command[j] {
				case '\\':
					j++
				case '\'':
					return j + 1
				}
			}
			return len(command)
		}
		if end := strings.IndexByte(command[i+1:], '\''); end >= 0 {
			return i + 1 + end + 1
		}
		return len(command)
	case '#':
		if i == 0 || strings.IndexByte(" \t\n;&|()", command[i-1]) >= 0 {
			if end := strings.IndexByte(command[i:], '\n'); end >= 0 {
				return i + end
			}
			return len(command)
		}
	case '<':
		if i+1 < len(command) && command[i+1] == '<' && (i+2 >= len(command) || command[i+2] != '<') && (i == 0 || command[i-1] != '<') {
			if spec, ok := heredocMarker(command, i+2); ok {
				*pending = append(*pending, spec)
			}
		}
	case '\n':
		if len(*pending) == 0 {
			return i
		}
		end := i + 1
		for _, spec := range *pending {
			end = heredocBodyEnd(command, end, spec)
		}
		*pending = (*pending)[:0]
		return end
	}
	return i
}

// heredocMarker reads the delimiter after << at command[i:].
func heredocMarker(command string, i int) (heredocSpec, bool) {
	spec := heredocSpec{plain: true}
	if i < len(command) && command[i] == '-' {
		spec.dash = true
		i++
	}
	for i < len(command) && (command[i] == ' ' || command[i] == '\t') {
		i++
	}
	start := i
	for i < len(command) {
		c := command[i]
		switch {
		case c == '\'' || c == '"':
			end := strings.IndexByte(command[i+1:], c)
			if end < 0 {
				return spec, false
			}
			spec.delim += command[i+1 : i+1+end]
			spec.plain = false
			i += end + 2
			continue
		case c == '\\' && i+1 < len(command):
			spec.delim += string(command[i+1])
			spec.plain = false
			i += 2
			continue
		case c == ' ' || c == '\t' || c == '\n' || c == ';' || c == '&' || c == '|' || c == '(' || c == ')' || c == '<' || c == '>':
		default:
			spec.delim += string(c)
			i++
			continue
		}
		break
	}
	return spec, i > start && spec.delim != ""
}

// heredocBodyEnd returns the end of the body of spec that starts at from:
// the end of the line that closes it, or of the text. The body of an
// unquoted here-document that holds a command substitution is not data: its
// start is returned.
func heredocBodyEnd(command string, from int, spec heredocSpec) int {
	for line := from; line < len(command); {
		eol := strings.IndexByte(command[line:], '\n')
		next := len(command)
		text := command[line:]
		if eol >= 0 {
			text, next = command[line:line+eol], line+eol+1
		}
		if spec.dash {
			text = strings.TrimLeft(text, "\t")
		}
		if text == spec.delim {
			if spec.plain && strings.ContainsAny(command[from:line], "`$") {
				return from
			}
			return next
		}
		line = next
	}
	if spec.plain && strings.ContainsAny(command[from:], "`$") {
		return from
	}
	return len(command)
}

// tokenBytes are the bytes that make a token of their own for MaxTokens:
// the separators and the operators of lists and arithmetic. Each makes a
// node at least, so counting them bounds the flat shapes (statements,
// arithmetic) the way the chain bytes bound the chains.
var tokenBytes = func() (table [256]bool) {
	for _, c := range []byte(";\n+-*/%^<>=?:,!~") {
		table[c] = true
	}
	return table
}()

// nestingBound is the first-stage check of nesting and brace expansion
// alone, for a reader that parses text it has already bounded as a whole
// (the nested-body measure).
func nestingBound(command string) string {
	depth, braces := 0, false
	for i := 0; i < len(command); i++ {
		switch c := command[i]; c {
		case '(', '{', '[':
			if depth++; depth > MaxNestingDepth {
				return BudgetNesting
			}
			braces = braces || c == '{'
		case ')', '}', ']':
			if depth > 0 {
				depth--
			}
		}
	}
	if braces && BraceExpansionTooLarge(command) {
		return BudgetBraces
	}
	return ""
}

// parseUnbudgeted is the parse of a text the first stage has bounded: the
// Bash grammar, then POSIX, as parseCommand reads it.
func parseUnbudgeted(command string) (*syntax.File, bool) {
	for _, variant := range []syntax.LangVariant{syntax.LangBash, syntax.LangPOSIX} {
		file, err := syntax.NewParser(syntax.Variant(variant)).Parse(strings.NewReader(command), "")
		if err == nil {
			return file, true
		}
	}
	return nil, false
}

var nodeType = reflect.TypeFor[syntax.Node]()

type measureFrame struct {
	value reflect.Value
	depth int
}

// measureTree counts the nodes, the depth and the chain operators of file
// with an explicit stack, not recursion, and returns the reason the tree is
// past the budget, or "". It stops at the first bound it passes, and
// bounds its own stack by the node bound.
func measureTree(file *syntax.File) string {
	nodes, chain := 0, 0
	stack := []measureFrame{{reflect.ValueOf(file), 0}}
	for len(stack) > 0 {
		if len(stack) > 4*MaxParsedNodes {
			return BudgetNodes
		}
		frame := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		value, depth := frame.value, frame.depth
		switch value.Kind() {
		case reflect.Pointer:
			if value.IsNil() {
				continue
			}
			if value.Type().Implements(nodeType) {
				if nodes++; nodes > MaxParsedNodes {
					return BudgetNodes
				}
				if depth++; depth > MaxTreeDepth {
					return BudgetDepth
				}
				if binary, ok := value.Interface().(*syntax.BinaryCmd); ok {
					switch binary.Op {
					case syntax.Pipe, syntax.PipeAll, syntax.AndStmt, syntax.OrStmt:
						if chain++; chain > MaxChainOperators {
							return BudgetChain
						}
					}
				}
			}
			stack = append(stack, measureFrame{value.Elem(), depth})
		case reflect.Interface:
			if !value.IsNil() {
				stack = append(stack, measureFrame{value.Elem(), depth})
			}
		case reflect.Slice:
			for i := range value.Len() {
				stack = append(stack, measureFrame{value.Index(i), depth})
			}
		case reflect.Struct:
			for i := range value.NumField() {
				if !value.Type().Field(i).IsExported() {
					continue
				}
				switch value.Field(i).Kind() {
				case reflect.Pointer, reflect.Interface, reflect.Slice, reflect.Struct:
					stack = append(stack, measureFrame{value.Field(i), depth})
				}
			}
		}
	}
	return ""
}
