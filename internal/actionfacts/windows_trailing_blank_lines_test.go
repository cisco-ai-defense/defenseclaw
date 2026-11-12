// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func lexWindowsForTest(t *testing.T, source string, dialect windowsDialect, kind Dialect) []windowsLexeme {
	t.Helper()
	out := newParseOutput(kind, 1)
	lexemes, ok := windowsLex(source, dialect, &out)
	if !ok {
		t.Fatalf("%q: the lexer gave up", source[:min(len(source), 80)])
	}
	return lexemes
}

// White space after the last word ends no statement: a command followed by
// any number of blank lines reads as the command followed by none, and a line
// ending that is followed by another word still ends the statement.
func TestWindowsLexTrailingBlankLinesEndNoStatement(t *testing.T) {
	t.Parallel()
	for _, d := range []struct {
		name    string
		dialect windowsDialect
		kind    Dialect
	}{{"powershell", windowsPowerShell, DialectPowerShell}, {"cmd", windowsCMD, DialectCMD}} {
		t.Run(d.name, func(t *testing.T) {
			t.Parallel()
			want := lexWindowsForTest(t, "echo ok > out.txt", d.dialect, d.kind)
			for name, tail := range map[string]string{
				"one line end":      "\n",
				"blank lines":       "\n  \n\r\n\t\n",
				"many blank lines":  strings.Repeat("\n  \n", 500),
				"white space first": "   \n \n",
			} {
				got := lexWindowsForTest(t, "echo ok > out.txt"+tail, d.dialect, d.kind)
				if !reflect.DeepEqual(got, want) {
					t.Errorf("%s: trailing %q changed the reading\n got: %#v\nwant: %#v", name, tail, got, want)
				}
			}
			for name, source := range map[string]string{
				"next word":          "echo ok\nwhoami",
				"blank lines before": "echo ok\n  \n\nwhoami",
				"blank lines around": "echo ok\n  \nwhoami\n  \n",
			} {
				separators := 0
				for _, lexeme := range lexWindowsForTest(t, source, d.dialect, d.kind) {
					if lexeme.kind == windowsSeparatorLexeme && lexeme.operator == "newline" {
						separators++
					}
				}
				if separators != 1 {
					t.Errorf("%s: %d newline separators, want 1: %q", name, separators, source)
				}
			}
		})
	}
}

// Reading a command that ends in n blank lines costs n steps, not n times
// the length of the tail (GAP-1014: a 35 KB tail of blank lines took 5 s
// outside -race, 50 s under it). Four times the size may take at most ten
// times as long (best of 5 tries, 50 ms for timer noise): a linear reading
// takes 4x, a quadratic one 16x. The ratio of two sizes four times apart
// leaves room for the timer and the garbage collector on a loaded runner,
// where a ratio of two sizes only twice apart (2.5x allowed) failed at 3.1x.
func TestWindowsLexTrailingBlankLinesCostGrowsLinearly(t *testing.T) {
	read := func(units int) time.Duration {
		source := "echo ok > out.txt" + strings.Repeat("  \n", units)
		best := time.Duration(-1)
		for try := 0; try < 5; try++ {
			start := time.Now()
			lexWindowsForTest(t, source, windowsPowerShell, DialectPowerShell)
			if elapsed := time.Since(start); best < 0 || elapsed < best {
				best = elapsed
			}
		}
		return best
	}
	const units = 5000
	small, large := read(units), read(4*units)
	t.Logf("%d blank lines %s, %d blank lines %s", units, small, 4*units, large)
	if large > small*10+50*time.Millisecond {
		t.Errorf("%d blank lines took %s and %d took %s: not linear (over 10x for 4x the size)", units, small, 4*units, large)
	}
}
