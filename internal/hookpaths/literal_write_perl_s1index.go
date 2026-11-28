// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "sort"

// perlS1Index answers perlS1ValueSpan for every call of one program from one
// pass over its tokens. perlS1ValueSpan read the whole token prefix of each
// call for each scalar it resolved, and the brace path from each earlier
// assignment of that scalar to the call: on token-dense code at the 16 KiB
// reader limit (an assignment and an open per statement) that grew with the
// square of the program, 2 KiB 0.8 ms to 16 KiB 18 ms (rel-1-0-10:GAP-2230).
// Each question is now a lookup, with the same answer.
type perlS1Index struct {
	// at maps a token start to its first token index (the call's token).
	at map[int]int
	// assigns are the ascending indexes of the "$name =" tokens that may be
	// an S1 assignment of name before any call: not escaped, not under a
	// statement modifier loop and not after a conditional word of their
	// statement. A call still checks that the = comes before it and that the
	// assignment encloses it.
	assigns map[string][]int
	// uses are the ascending indexes of every $name and ${name} token.
	uses map[string][]int
	// opaque are the ascending indexes where perlOpaqueAt holds.
	opaque []int
	// depth[i] is the brace depth before token i; lower[i] is the first
	// j > i with depth[j] < depth[i] (len(tokens)+1 when there is none), so
	// the path from i to a call at c closes a brace i did not open exactly
	// when lower[i] <= c.
	depth, lower []int
	// barriers[i] counts the { tokens among tokens[:i] that open a sub or
	// loop block.
	barriers []int
	// term[i] is the first j >= i whose token is ;, "," or ) (len(tokens)
	// when there is none): the end of a value that starts at i.
	term []int
}

// perlS1Lazy builds the index of a program on its first question: most
// programs have no scalar mode or flag to resolve. A nil perlS1Lazy builds a
// fresh index per question.
type perlS1Lazy struct {
	index *perlS1Index
	vis   *perlVisIndex
}

func (lazy *perlS1Lazy) of(tokens []perlToken) *perlS1Index {
	if lazy == nil {
		return newPerlS1Index(tokens)
	}
	if lazy.index == nil {
		lazy.index = newPerlS1Index(tokens)
	}
	return lazy.index
}

func newPerlS1Index(tokens []perlToken) *perlS1Index {
	n := len(tokens)
	index := &perlS1Index{
		at:       make(map[int]int, n),
		assigns:  map[string][]int{},
		uses:     map[string][]int{},
		depth:    make([]int, n+1),
		lower:    make([]int, n+1),
		barriers: make([]int, n+1),
		term:     make([]int, n+1),
	}
	conditional := false
	for i := range tokens {
		if _, seen := index.at[tokens[i].start]; !seen {
			index.at[tokens[i].start] = i
		}
		index.depth[i+1], index.barriers[i+1] = index.depth[i], index.barriers[i]
		text := tokens[i].text
		switch text {
		case "{":
			index.depth[i+1]++
			if i+1 < n && (tokens[i+1].blockKind == "sub" || tokens[i+1].blockKind == "loop") {
				index.barriers[i+1]++
			}
		case "}":
			index.depth[i+1]--
		}
		if name, next := perlScalarAt(tokens, i); name != "" {
			index.uses[name] = append(index.uses[name], i)
			if next < n && tokens[next].text == "=" && !tokens[i].modifierLoop &&
				(i == 0 || tokens[i-1].text != string(rune(92))) && !conditional {
				index.assigns[name] = append(index.assigns[name], i)
			}
		}
		if perlOpaqueAt(tokens, i) {
			index.opaque = append(index.opaque, i)
		}
		switch text {
		case ";", "{", "}":
			conditional = false
		case "if", "unless", "while", "until", "for", "foreach":
			conditional = true
		}
	}
	// lower: the next smaller depth, by a stack of indexes whose answer is
	// still open (their depths do not decrease up the stack).
	var open []int
	for j := 0; j <= n; j++ {
		for len(open) > 0 && index.depth[j] < index.depth[open[len(open)-1]] {
			index.lower[open[len(open)-1]] = j
			open = open[:len(open)-1]
		}
		open = append(open, j)
	}
	for _, i := range open {
		index.lower[i] = n + 1
	}
	index.term[n] = n
	for i := n - 1; i >= 0; i-- {
		switch tokens[i].text {
		case ";", ",", ")":
			index.term[i] = i
		default:
			index.term[i] = index.term[i+1]
		}
	}
	return index
}

// encloses is perlS1Enclosing: from the assignment at a to the call at c the
// path opens no sub or loop block and closes no brace a did not open.
func (index *perlS1Index) encloses(a, c int) bool {
	return index.barriers[c] == index.barriers[a] && index.lower[a] > c
}

// within reports an entry of the ascending list in [from, to).
func perlIndexWithin(list []int, from, to int) bool {
	k := sort.SearchInts(list, from)
	return k < len(list) && list[k] < to
}
