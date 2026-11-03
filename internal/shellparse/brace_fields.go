// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import (
	"strconv"

	"mvdan.cc/sh/v3/syntax"
)

// MinBraceFields is a lower bound on the fields that expand.Fields makes of
// word through its brace ranges, read from the syntax without expanding:
// the element count of its largest {x..y[..s]} range. Each element of a
// range is a non-empty literal, so every word the range expands to keeps at
// least one field, wherever the range sits (after a prefix, inside a list
// alternative). A reader that wants one field, or at most a few, can refuse
// such a word before expand.Fields builds them all: a benign echo
// {1..60000} cost each of the dozens of word readers of a hook call one full
// expansion and ran past the hook deadline (GAP-0568). Lists ({a,b}) count
// nothing here, because an empty alternative makes no field.
func MinBraceFields(word *syntax.Word) uint64 {
	if word == nil {
		return 0
	}
	split := *word // SplitBraces replaces the Parts slice, never the parts
	if !syntax.SplitBraces(&split) {
		return 0
	}
	return minRangeFields(split.Parts)
}

func minRangeFields(parts []syntax.WordPart) uint64 {
	var most uint64
	for _, part := range parts {
		brace, ok := part.(*syntax.BraceExp)
		if !ok {
			continue
		}
		if brace.Sequence {
			most = max(most, rangeElements(brace))
			continue
		}
		for _, elem := range brace.Elems {
			most = max(most, minRangeFields(elem.Parts))
		}
	}
	return most
}

// rangeElements counts the elements of a range exactly as expand.Braces
// walks it: integer ends, or else the first byte of each end, and a step
// that is used only when it is non-zero and points from the start to the
// end.
func rangeElements(brace *syntax.BraceExp) uint64 {
	if len(brace.Elems) < 2 {
		return 0
	}
	fromLit, toLit := brace.Elems[0].Lit(), brace.Elems[1].Lit()
	from, err1 := strconv.Atoi(fromLit)
	to, err2 := strconv.Atoi(toLit)
	if err1 != nil || err2 != nil {
		if fromLit == "" || toLit == "" {
			return 0
		}
		from, to = int(fromLit[0]), int(toLit[0])
	}
	upward := from <= to
	var span uint64
	if upward {
		span = uint64(to) - uint64(from)
	} else {
		span = uint64(from) - uint64(to)
	}
	step := uint64(1)
	if len(brace.Elems) > 2 {
		n, _ := strconv.Atoi(brace.Elems[2].Lit())
		if n != 0 && n > 0 == upward {
			if n < 0 {
				step = uint64(-int64(n))
			} else {
				step = uint64(n)
			}
		}
	}
	return span/step + 1
}
