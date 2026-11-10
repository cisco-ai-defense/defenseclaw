// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// MaxOperandsPerStatement is the most operands of one statement that the
// readers of a hook call judge with the file system (GAP-0943, GAP-0963).
// Every operand costs a few reads of the file system, about a millisecond on
// a Windows host, so a statement of thousands of operands kept the call past
// the hook answer window while the gateway was up. Past this bound the call
// is unresolved and the policy tier decides (a visible alert in the default
// and permissive tiers, the evaluation-limit block in the strict tier); no
// operand is dropped without that verdict.
const MaxOperandsPerStatement = 1024

// BoundOperands reads command lexically (quotes, statement separators, no
// file system) and reports over when one statement has more than
// MaxOperandsPerStatement operands. reduced is then the command without the
// operands past that bound that droppable calls plain (it must hold for a
// word that cannot name a protected file or link by itself); every other
// operand past the bound stays, up to another MaxOperandsPerStatement of
// them. The redirections of a statement and their targets are no operands
// and stay. When over is false
// reduced is command itself.
func BoundOperands(command string, droppable func(word string) bool) (reduced string, over bool) {
	// A statement over the bound has more than MaxOperandsPerStatement words
	// of at least a byte and a separator each.
	if len(command) < 2*MaxOperandsPerStatement {
		return command, false
	}
	var out strings.Builder
	words, suspect, n := 0, 0, len(command)
	keepNext := false
	for i := 0; i < n; {
		c := command[i]
		switch {
		case c == 0x20 || c == 0x09 || c == 0x0d:
			out.WriteByte(c)
			i++
			continue
		case statementSeparator(command, i):
			words, suspect, keepNext = 0, 0, false
			out.WriteByte(c)
			i++
			continue
		}
		end := wordEnd(command, i)
		word := command[i:end]
		i = end
		switch {
		case redirectWord(word):
			// A redirection and its target are no operands: they stay.
			out.WriteString(word)
			keepNext = redirectOperator(word)
			continue
		case keepNext:
			out.WriteString(word)
			keepNext = false
			continue
		}
		words++
		if words <= MaxOperandsPerStatement+1 {
			out.WriteString(word)
			continue
		}
		over = true
		if !droppable(word) && suspect < MaxOperandsPerStatement {
			out.WriteString(word)
			suspect++
		}
	}
	if !over {
		return command, false
	}
	return out.String(), true
}

// statementSeparator reports a byte of command that ends a statement: a
// line break, a semicolon, a pipe, a parenthesis, or a background ampersand
// (not the one of a redirection such as 2>&1 or &>).
func statementSeparator(command string, i int) bool {
	switch command[i] {
	case 0x0a, 0x3b, 0x7c, 0x28, 0x29:
		return true
	case 0x26:
		return (i == 0 || command[i-1] != 0x3e && command[i-1] != 0x3c) &&
			(i+1 >= len(command) || command[i+1] != 0x3e)
	}
	return false
}

// wordEnd is the end of the word that starts at i: it runs to the next blank
// or statement separator outside quotes; a backslash or backtick escapes the
// next byte.
func wordEnd(command string, i int) int {
	n := len(command)
	var quote byte
	for j := i; j < n; j++ {
		c := command[j]
		switch {
		case quote != 0:
			switch {
			case c == quote:
				quote = 0
			case c == 0x5c && quote == 0x22 && j+1 < n:
				j++
			}
		case c == 0x27 || c == 0x22:
			quote = c
		case (c == 0x5c || c == 0x60) && j+1 < n && command[j+1] != 0x0a:
			j++
		case c == 0x20 || c == 0x09 || c == 0x0d || statementSeparator(command, j):
			if j > i {
				return j
			}
		}
	}
	return n
}

// redirectWord reports a word that starts a redirection: an optional file
// descriptor and one of the redirection operators.
func redirectWord(word string) bool {
	rest := strings.TrimLeft(word, "0123456789")
	return strings.HasPrefix(rest, ">") || strings.HasPrefix(rest, "<") || strings.HasPrefix(rest, "&>")
}

// redirectOperator reports a redirection word with no target of its own, so
// the next word is the target.
func redirectOperator(word string) bool {
	if !redirectWord(word) {
		return false
	}
	rest := strings.TrimLeft(word, "0123456789")
	rest = strings.TrimLeft(rest, "<>&|")
	return rest == "" && !strings.HasSuffix(word, "&")
}
