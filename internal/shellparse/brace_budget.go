// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import "strconv"

// MaxBraceFields and MaxBraceBytes bound the words, and the bytes, that the
// brace expansions of one command produce. A shell reader that expands a
// word (expand.Fields) builds every field in memory: a one-word range of
// 10^8 elements pinned a per-user gateway at a 2 GiB memory cap and, with no
// cap, hung its host (rel-1-0-6 GAP-0187; GAP-0568). The cost is computed
// from the text before anything expands. No ordinary command comes near it:
// mkdir -p src/{a,b,c}/{x,y} is 6 words.
const (
	MaxBraceFields = 1 << 16
	MaxBraceBytes  = 4 << 20
)

// BraceExpansionTooLarge reports whether the brace expansions of command
// would produce more than MaxBraceFields words or MaxBraceBytes bytes, in
// one linear pass over the text. A {a,b} list counts its alternatives, a
// {x..y[..s]} range of integers or single letters its elements, adjacent
// and nested groups multiply, and a word counts its fields times its
// length. Quoted and escaped braces do not expand; a brace that cannot
// expand counts once. The estimate never undercounts a word the shell
// expands, so a command it passes cannot blow up a reader.
func BraceExpansionTooLarge(command string) bool {
	var fields, bytes float64
	for start := 0; start < len(command); {
		end := wordEnd(command, start)
		if end > start {
			word := command[start:end]
			n := wordBraceFields(word)
			fields += n
			bytes += n * float64(len(word))
			if fields > MaxBraceFields || bytes > MaxBraceBytes {
				return true
			}
			start = end
			continue
		}
		start++
	}
	return false
}

// wordEnd returns the end of the shell word that starts at i: the first
// unquoted blank or operator byte. Quotes and escapes stay in the word.
func wordEnd(command string, i int) int {
	var quote byte
	for ; i < len(command); i++ {
		c := command[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
		case c == '\\':
			i++
		case quote == '"':
			if c == '"' {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == ' ' || c == '\t' || c == '\n' || c == ';' || c == '&' || c == '|' ||
			c == '<' || c == '>' || c == '(' || c == ')':
			return i
		}
	}
	// A trailing backslash escapes past the end.
	return min(i, len(command))
}

// wordBraceFields is the number of fields word expands to: the product of
// its unquoted brace groups.
func wordBraceFields(word string) float64 {
	n, _ := braceSequence(word, 0, false)
	return n
}

// braceSequence reads word from i up to the end, or (inGroup) up to an
// unquoted , or } of the enclosing group, and returns the product of the
// brace groups in it and where it stopped.
func braceSequence(word string, i int, inGroup bool) (float64, int) {
	product := 1.0
	var quote byte
	for i < len(word) {
		c := word[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
		case c == '\\':
			i++
		case quote == '"':
			if c == '"' {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case inGroup && (c == ',' || c == '}'):
			return product, i
		case c == '$' && i+1 < len(word) && word[i+1] == '{':
			// ${...} is a parameter, not a brace group.
			i = skipGroup(word, i+2)
			continue
		case c == '{':
			count, next := braceGroup(word, i)
			product *= count
			if product > MaxBraceFields*MaxBraceBytes {
				product = MaxBraceFields * MaxBraceBytes
			}
			i = next
			continue
		}
		i++
	}
	return product, i
}

// braceGroup reads the group that opens at word[open] and returns its field
// count and the index after it. A group with no closing brace, or one with
// neither a top-level comma nor a valid range, counts once.
func braceGroup(word string, open int) (float64, int) {
	if count, end, ok := braceRange(word, open); ok {
		return count, end
	}
	sum := 0.0
	alternatives := 0
	i := open + 1
	for i < len(word) {
		n, stop := braceSequence(word, i, true)
		sum += n
		alternatives++
		if stop >= len(word) {
			return 1, len(word)
		}
		if word[stop] == '}' {
			if alternatives < 2 {
				return n, stop + 1
			}
			return sum, stop + 1
		}
		i = stop + 1
	}
	return 1, len(word)
}

// braceRange reads {x..y} or {x..y..s} at word[open], with integer or
// single-letter ends, and returns its element count.
func braceRange(word string, open int) (float64, int, bool) {
	close := open + 1
	for close < len(word) && word[close] != '}' && close-open <= 64 {
		close++
	}
	if close >= len(word) || word[close] != '}' {
		return 0, 0, false
	}
	parts := splitDots(word[open+1 : close])
	if len(parts) != 2 && len(parts) != 3 {
		return 0, 0, false
	}
	step := 1.0
	if len(parts) == 3 {
		s, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			return 0, 0, false
		}
		if s < 0 {
			s = -s
		}
		if s > 1 {
			step = float64(s)
		}
	}
	if lo, err := strconv.ParseInt(parts[0], 10, 64); err == nil {
		hi, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return 0, 0, false
		}
		span := float64(hi) - float64(lo)
		if span < 0 {
			span = -span
		}
		return span/step + 1, close + 1, true
	}
	if len(parts[0]) == 1 && len(parts[1]) == 1 {
		span := float64(parts[1][0]) - float64(parts[0][0])
		if span < 0 {
			span = -span
		}
		return span/step + 1, close + 1, true
	}
	return 0, 0, false
}

// splitDots splits a range body at "..".
func splitDots(body string) []string {
	var parts []string
	start := 0
	for i := 0; i+1 < len(body); i++ {
		if body[i] == '.' && body[i+1] == '.' {
			parts = append(parts, body[start:i])
			start = i + 2
			i++
		}
	}
	return append(parts, body[start:])
}

// skipGroup returns the index after the } that closes a ${ opened before i.
func skipGroup(word string, i int) int {
	depth := 1
	for ; i < len(word); i++ {
		switch word[i] {
		case '{':
			depth++
		case '}':
			if depth--; depth == 0 {
				return i + 1
			}
		}
	}
	return i
}
