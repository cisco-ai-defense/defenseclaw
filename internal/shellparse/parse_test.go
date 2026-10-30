// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import (
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"mvdan.cc/sh/v3/syntax"
)

func TestTooDeep(t *testing.T) {
	for _, tc := range []struct {
		command string
		deep    bool
	}{
		{"echo hi", false},
		{"find . \\( -name a -o -name b \\) -print", false},
		{strings.Repeat("(", MaxNestingDepth) + strings.Repeat(")", MaxNestingDepth), false},
		{strings.Repeat("(", MaxNestingDepth+1), true},
		{strings.Repeat("$(", MaxNestingDepth+1), true},
		{strings.Repeat("{ ", MaxNestingDepth+1), true},
		{strings.Repeat("[", MaxNestingDepth+1), true},
		// Balanced siblings never add up.
		{strings.Repeat("(a) ", 10*MaxNestingDepth), false},
		{strings.Repeat(")", 10) + strings.Repeat("(", MaxNestingDepth), false},
	} {
		if got := TooDeep(tc.command); got != tc.deep {
			t.Errorf("TooDeep(%.40q...) = %v, want %v", tc.command, got, tc.deep)
		}
	}
}

// A command of 180 KiB of ( made the parser recurse past the goroutine stack
// limit, a fatal error (GAP-2537). With a 64 MiB stack bound the deep forms
// are refused at once and an ordinary nesting still parses.
func TestParseRefusesDeepNestingWithoutRecursing(t *testing.T) {
	defer debug.SetMaxStack(debug.SetMaxStack(64 << 20))
	for _, unit := range []string{"(", "$(", "$((", "{ ", "[", "\"$("} {
		command := strings.Repeat(unit, (180<<10)/len(unit)) + "\necho done"
		start := time.Now()
		if _, ok := Parse(command); ok {
			t.Errorf("unit %q: deep command parsed", unit)
		}
		if took := time.Since(start); took > time.Second {
			t.Errorf("unit %q: refused in %s", unit, took)
		}
	}
	nested := strings.Repeat("$(echo ", 64) + "x" + strings.Repeat(")", 64)
	if _, ok := Parse("echo " + nested); !ok {
		t.Error("64-level command substitution did not parse")
	}
}

// Reader refuses a deep command as a read error, so a caller that hands it
// to its own syntax.Parser gets that error instead of a recursion
// (GAP-2556).
func TestReaderRefusesDeepNesting(t *testing.T) {
	defer debug.SetMaxStack(debug.SetMaxStack(64 << 20))
	for _, unit := range []string{"(", "$(", "$((", "{ ", "["} {
		command := strings.Repeat(unit, (180<<10)/len(unit)) + "\necho done"
		if _, err := syntax.NewParser().Parse(Reader(command), ""); err == nil {
			t.Errorf("unit %q: deep command parsed", unit)
		}
	}
	if _, err := syntax.NewParser().Parse(Reader("(cd src && (make && (echo ok)))"), ""); err != nil {
		t.Errorf("ordinary nesting: %v", err)
	}
}
