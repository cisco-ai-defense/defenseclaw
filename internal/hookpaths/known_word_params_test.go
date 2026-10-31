// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"slices"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// rel-1-0-2:GAP-0004: an unquoted copy source reads as one plain word only
// when every binding of its name gives it a fixed plain value that cannot be
// an option, and the use runs after such a binding.
func TestUnquotedCopySourceIsOneKnownWordOnlyWithOneFixedPlainValue(t *testing.T) {
	const home = "/home/u"
	known := []string{
		`for f in a.txt README.md; do cp $f build/; done`,
		`f=a.txt; cp $f out.txt`,
		`f=a.txt && cp ${f} out.txt`,
		`v=a.txt; cp $v out.txt && echo ok`,
		`for f in a.txt ~/notes.txt; do cp $f build/; done`,
	}
	unknown := []string{
		`cp $f out.txt`,
		`for f in *.txt; do cp $f build/; done`,
		`for f in 'a b'; do cp $f build/; done`,
		`for f in -s; do cp $f build/; done`,
		`for f; do cp $f build/; done`,
		`select f in a.txt; do cp $f build/; done`,
		`for ((i=0; i<1; i++)); do cp $f build/; done`,
		`f=a.txt; read f; cp $f out.txt`,
		`f=a.txt; eval true; cp $f out.txt`,
		`f=a.txt; printf -v f x; cp $f out.txt`,
		`IFS=.; f=a.txt; cp $f out.txt`,
		`f=a.txt cp $f out.txt`,
		`cp $f out.txt; f=a.txt`,
		`if true; then f=a.txt; fi; cp $f out.txt`,
		`f=a.txt; f=$X; cp $f out.txt`,
		`f=a.txt; f+=x; cp $f out.txt`,
		`f=a.txt; : ${f:=x}; cp $f out.txt`,
		`f=a.txt; g() { :; }; cp $f out.txt`,
		`f=a.txt; $run; cp $f out.txt`,
		`f=a.txt & cp $f out.txt`,
		`false && f=a.txt; cp $f out.txt`,
		`f=--target-directory=x; cp $f out.txt`,
		`f=a.txt; export f=b; cp $f out.txt`,
		`f=a.txt; (( f = 1 )); cp $f out.txt`,
	}
	source := func(t *testing.T, command string) (*syntax.File, *syntax.Word) {
		t.Helper()
		file, ok := parseShell(command)
		if !ok {
			t.Fatalf("%s does not parse", command)
		}
		var word *syntax.Word
		syntax.Walk(file, func(node syntax.Node) bool {
			if call, ok := node.(*syntax.CallExpr); ok && len(call.Args) == 3 {
				if program, _ := StaticWord(call.Args[0], home); program == "cp" {
					word = call.Args[1]
				}
			}
			return true
		})
		if word == nil {
			t.Fatalf("%s has no cp call", command)
		}
		return file, word
	}
	for _, command := range known {
		file, word := source(t, command)
		if !knownWordParameterUses(file, home)[word] {
			t.Errorf("%s: copy source not read as one known word", command)
		}
	}
	for _, command := range unknown {
		file, word := source(t, command)
		if knownWordParameterUses(file, home)[word] {
			t.Errorf("%s: copy source read as one known word", command)
		}
	}
	if got := QuotedDynamicCopyDestinations(`f=a.txt; cp $f out.txt`, "/p", home); !slices.Equal(got, []string{"/p/out.txt"}) {
		t.Errorf("fixed destination of a known unquoted source = %v", got)
	}
}
