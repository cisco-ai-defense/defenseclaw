// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// copyGlobOperand stands, in the argv a copy call is read from, for a source
// word that the shell expands at run time (a glob such as /etc/pam.d/*) but
// that cannot expand to an option. It is never a path the walk opens.
const copyGlobOperand = "\x00copy-glob"

// copyGlobOperandsAsNames reads each non-final copy word that expands at run
// time but starts with a fixed name character as one more source name. The
// shell never turns such a word into an option, so it cannot move the
// destination or make the copy keep links. Without this, cpOperands read any
// expanding word as "may be an option", left the destination unknown, and
// opened a global copy scope that made every later write of the command (a
// second cp, a mv, a redirect) an authorized-keys block, as for
// cp /etc/pam.d/* /backup/ && cp a b (rel-1-0-10:GAP-0018).
//
// The final word stays as read: a destination that is not static is unknown.
// A call with an option that takes its value from the next word, or any
// option the walk does not know, keeps the old reading, so a glob there may
// still be the value of -t or -S.
func copyGlobOperandsAsNames(args []*syntax.Word, words []string, static []bool) ([]string, []bool) {
	if len(args) < 3 || len(words) != len(args) || len(static) != len(args) {
		return words, static
	}
	var out []string
	var outStatic []bool
	options := true
	for i := 1; i < len(args)-1; i++ {
		if static[i] {
			word := words[i]
			if options && word == "--" {
				options = false
			} else if options && strings.HasPrefix(word, "-") && word != "-" && !copyOptionKeepsNoValue(word) {
				return words, static
			}
			continue
		}
		if !copyWordKeepsFirstByte(args[i]) {
			return words, static
		}
		if out == nil {
			out, outStatic = slices.Clone(words), slices.Clone(static)
		}
		out[i], outStatic[i] = copyGlobOperand, true
	}
	if out == nil {
		return words, static
	}
	return out, outStatic
}

// copyOptionKeepsNoValue reports a static copy option that takes no value
// from the next word and is known to the walk.
func copyOptionKeepsNoValue(option string) bool {
	if strings.HasPrefix(option, "--") {
		switch option {
		case "--recursive", "--archive", "--verbose", "--force", "--interactive",
			"--no-clobber", "--update", "--dereference", "--no-dereference",
			"--preserve", "--parents", "--remove-destination", "--no-target-directory":
			return true
		}
		return false
	}
	for _, c := range option[1:] {
		if !strings.ContainsRune("abcdfHiLlnPpRrsTuvxZ", c) {
			return false
		}
	}
	return true
}

// copyWordKeepsFirstByte reports a word whose first part is a literal that
// starts with a name character, so no expansion of the rest can put a dash
// first.
func copyWordKeepsFirstByte(word *syntax.Word) bool {
	if word == nil || len(word.Parts) == 0 {
		return false
	}
	lit, ok := word.Parts[0].(*syntax.Lit)
	if !ok || lit.Value == "" {
		return false
	}
	c := lit.Value[0]
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '/' || c == '.' || c == '_' || c == '~'
}
