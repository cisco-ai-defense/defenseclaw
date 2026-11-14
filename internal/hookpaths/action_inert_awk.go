// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "mvdan.cc/sh/v3/syntax"

// actionInertAwkPrograms returns the words of an awk call that hold its
// inline program text (an operand, or the value of -e). The program is judged
// where awk output is read (awkOutputProof: strings, regular expression
// literals and comments are data), so the raw-text mention scan must not
// read a quoted name inside a regular expression as a target. The input
// operands and a -f program file stay ordinary words.
func actionInertAwkPrograms(call *syntax.CallExpr, home string) []*syntax.Word {
	if call == nil || len(call.Args) < 2 {
		return nil
	}
	program, fixed := staticProgramWord(call.Args[0], home)
	if !fixed {
		return nil
	}
	switch programBase(program) {
	case "awk", "gawk", "mawk", "nawk":
	default:
		return nil
	}
	// A word that is not fixed text is an input operand or an assignment as
	// far as the program reading goes; it cannot be a program.
	words := make([]string, len(call.Args))
	for i, arg := range call.Args {
		text, fixed := StaticWord(arg, home)
		if !fixed {
			text = "\x00input"
		}
		words[i] = text
	}
	programs, _ := awkProgramWords(words)
	if len(programs) == 0 {
		return nil
	}
	var out []*syntax.Word
	for i := 1; i < len(call.Args); i++ {
		for _, text := range programs {
			if words[i] == text && words[i] != "\x00input" {
				out = append(out, call.Args[i])
				break
			}
		}
	}
	return out
}
