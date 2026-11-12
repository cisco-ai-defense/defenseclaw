// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import (
	"errors"
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// ErrBraceFieldsTooLarge is the error of Fields for a word whose brace
// expansion is past MaxBraceFields words or MaxBraceBytes bytes.
var ErrBraceFieldsTooLarge = errors.New("shellparse: brace expansion past the reading bound")

// Fields is expand.Fields behind the brace bound. The command-level check
// (BraceExpansionTooLarge) reads a command word by word, split at blanks,
// but a reader expands a syntax word, and a here-document body is one word
// with blanks inside it: its brace groups multiply. A benign 4 KB here-document
// of JavaScript with fifteen destructuring lists (about 2*10^7 fields) kept the
// evaluator of one hook call busy for minutes (GAP-0700). Every reader that
// expands a word calls Fields, so the bound holds for any word it is handed.
func Fields(cfg *expand.Config, word *syntax.Word) ([]string, error) {
	if BraceFieldsTooLarge(word) {
		return nil, ErrBraceFieldsTooLarge
	}
	return expand.Fields(cfg, word)
}

// BraceFieldsTooLarge reports whether expand.Fields would make more than
// MaxBraceFields fields, or more than MaxBraceBytes bytes, of word. It reads
// the brace groups from the syntax without expanding: a {a,b} list counts its
// alternatives, a {x..y} range its elements, and the groups of one word
// multiply. A word with no brace group is never too large.
func BraceFieldsTooLarge(word *syntax.Word) bool {
	if word == nil || !wordHasBraceText(word) {
		return false
	}
	split := *word // SplitBraces replaces the Parts slice, never the parts
	if !syntax.SplitBraces(&split) {
		return false
	}
	fields := braceFields(split.Parts)
	if fields > MaxBraceFields {
		return true
	}
	size := 0
	for _, part := range word.Parts {
		if lit, ok := part.(*syntax.Lit); ok {
			size += len(lit.Value)
		}
	}
	return fields*float64(size) > MaxBraceBytes
}

// wordHasBraceText reports a literal part with a brace, the only place a
// brace group can start: the common word has none and is not split.
func wordHasBraceText(word *syntax.Word) bool {
	for _, part := range word.Parts {
		if lit, ok := part.(*syntax.Lit); ok && strings.Contains(lit.Value, "{") {
			return true
		}
	}
	return false
}

// braceFields is the number of fields the brace groups of parts make: the
// product of the groups, each the sum of its alternatives. The result
// saturates, so a long run of groups cannot reach +Inf.
func braceFields(parts []syntax.WordPart) float64 {
	const saturated = MaxBraceFields * MaxBraceBytes
	product := 1.0
	for _, part := range parts {
		brace, ok := part.(*syntax.BraceExp)
		if !ok {
			continue
		}
		count := 0.0
		if brace.Sequence {
			count = float64(rangeElements(brace))
		} else {
			for _, elem := range brace.Elems {
				count += braceFields(elem.Parts)
			}
		}
		product = min(product*max(count, 1), saturated)
	}
	return product
}
