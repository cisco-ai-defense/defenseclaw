// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import (
	"reflect"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

func largeHeredocCommand(body string) string {
	return "apply_patch <<\x27PATCH\x27\n*** Begin Patch\n" + strings.Repeat(body, largeCommandMin/len(body)+1) + "*** End Patch\nPATCH\ncat notes.txt | wc -l && echo done\n"
}

func nodePointers(t *testing.T, file *syntax.File) map[syntax.Node]bool {
	t.Helper()
	nodes := map[syntax.Node]bool{}
	syntax.Walk(file, func(node syntax.Node) bool {
		if node != nil {
			nodes[node] = true
		}
		return true
	})
	return nodes
}

// TestParseOfLargeCommandHandsEveryCallerItsOwnTree pins that a large command
// is kept after its first parse (so the proofs of one hook call do not parse
// it twenty times), that every caller still receives a tree equal to a fresh
// parse that shares no node with another caller, and that rewriting one
// callers tree changes neither the next caller nor a fresh parse.
func TestParseOfLargeCommandHandsEveryCallerItsOwnTree(t *testing.T) {
	for _, comments := range []bool{false, true} {
		command := largeHeredocCommand("+ordinary line of a notes file # not a comment\n") + "# a real comment\n"
		parse := Parse
		if comments {
			parse = ParseWithComments
		}
		fresh, ok, _ := parseCommand(command, comments)
		if !ok {
			t.Fatal("the large command does not parse")
		}
		first, ok := parse(command)
		if !ok {
			t.Fatal("first Parse failed")
		}
		parseCache.Lock()
		kept := len(parseCache.entries)
		parseCache.Unlock()
		if kept == 0 {
			t.Fatal("the large command was not kept")
		}
		second, _ := parse(command)
		third, _ := parse(command)
		for name, file := range map[string]*syntax.File{"first": first, "second": second, "third": third} {
			if !reflect.DeepEqual(file, fresh) {
				t.Fatalf("comments=%t: %s tree differs from a fresh parse", comments, name)
			}
		}
		seen := nodePointers(t, first)
		for node := range nodePointers(t, second) {
			if seen[node] {
				t.Fatalf("comments=%t: two callers share a node", comments)
			}
		}
		// A caller rewrites its tree in place.
		syntax.Walk(second, func(node syntax.Node) bool {
			if lit, ok := node.(*syntax.Lit); ok {
				lit.Value = "rewritten"
			}
			return true
		})
		if again, _ := parse(command); !reflect.DeepEqual(again, fresh) {
			t.Fatalf("comments=%t: a rewritten tree changed the next caller", comments)
		}
	}
}

// TestParseOfLargeUnparsableCommandStaysUnparsable and the small-command case
// pin that the cache keeps the failure of a large command and never holds a
// command under the bound.
func TestParseOfLargeUnparsableCommandStaysUnparsable(t *testing.T) {
	broken := "echo \"" + strings.Repeat("unterminated quote ", largeCommandMin/10)
	for range 2 {
		if file, ok := Parse(broken); ok || file != nil {
			t.Fatalf("an unterminated large command parsed: ok=%t", ok)
		}
	}
	parseCache.Lock()
	parseCache.entries = nil
	parseCache.Unlock()
	for range 2 {
		if _, ok := Parse("ls -la && echo done"); !ok {
			t.Fatal("small command does not parse")
		}
	}
	parseCache.Lock()
	kept := len(parseCache.entries)
	parseCache.Unlock()
	if kept != 0 {
		t.Fatalf("a small command was kept (%d entries)", kept)
	}
}

// TestTooDeepOfLargeCommandFollowsTheText pins that the remembered nesting
// answer of the last large command never answers for another text of the same
// size.
func TestTooDeepOfLargeCommandFollowsTheText(t *testing.T) {
	flat := strings.Repeat("a", largeCommandMin+10)
	deep := strings.Repeat("(", MaxNestingDepth+1) + strings.Repeat("a", largeCommandMin+10-MaxNestingDepth-1)
	if len(flat) != len(deep) {
		t.Fatal("test texts differ in size")
	}
	for range 2 {
		if TooDeep(flat) {
			t.Fatal("flat text reads as too deep")
		}
		if !TooDeep(deep) {
			t.Fatal("deep text reads as shallow")
		}
	}
}
