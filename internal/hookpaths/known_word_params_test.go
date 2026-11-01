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
		// rel-1-0-2:GAP-0004 review: a wrapper, a deferred string or a
		// binding builtin outside the old deny list rebinds the name.
		`f=a.txt; command read f; cp $f out.txt`,
		`f=a.txt; wait -p f; cp $f out.txt`,
		`f=a.txt; trap "read f" DEBUG; cp $f out.txt`,
		`f=a.txt; command eval "$X"; cp $f out.txt`,
		`for f in a.txt; do command read f; cp $f build/; done`,
		`f=a.txt; builtin read f; cp $f out.txt`,
		`f=a.txt; exec 3<x; cp $f out.txt`,
		`f=a.txt; env -S x; cp $f out.txt`,
		`f=a.txt; cd build; cp $f out.txt`,
		`f=a.txt; mapfile f; cp $f out.txt`,
		`f=a.txt; getopts ab f; cp $f out.txt`,
		`f=a.txt; \read f; cp $f out.txt`,
		// rel-1-0-6:GAP-0235 review: names bash sets itself, and
		// arithmetic that assigns (a test clause, an index, a slice).
		`_=a.txt; echo disklink; cp $_ out.txt`,
		`for _ in a.txt; do echo -t; cp $_ build/; done`,
		`f=a.txt; [[ f=-7 -eq -7 ]]; cp $f out.txt`,
		`f=a.txt; echo ${a[f=-3]}; cp $f out.txt`,
		`f=a.txt; echo ${x:f=1}; cp $f out.txt`,
		`f=a.txt; a[f=-3]=x; cp $f out.txt`,
		`f=a.txt; echo $((f=1)); cp $f out.txt`,
		`f=a.txt; let f=1; cp $f out.txt`,
		`f=a.txt; a=([f=1]=x); cp $f out.txt`,
		`RANDOM=a.txt; cp $RANDOM out.txt`,
		`SECONDS=a.txt; cp $SECONDS out.txt`,
		`LINENO=a.txt; cp $LINENO out.txt`,
		`BASH_COMMAND=a.txt; cp $BASH_COMMAND out.txt`,
		`PWD=a.txt; cp $PWD out.txt`,
		`OLDPWD=a.txt; cp $OLDPWD out.txt`,
		`REPLY=a.txt; cp $REPLY out.txt`,
		`OPTARG=a.txt; cp $OPTARG out.txt`,
		`HOME=a.txt; cp $HOME out.txt`,
		`PATH=a.txt; cp $PATH out.txt`,
		`BASH_X=a.txt; cp $BASH_X out.txt`,
		`f=a.txt; test -v "a[f=-3]"; cp $f out.txt`,
		`f=a.txt; [ -v "a[f=-3]" ]; cp $f out.txt`,
		// Builtins and bodies the allowlist keeps unknown.
		`f=a.txt; source x; cp $f out.txt`,
		`f=a.txt; . x; cp $f out.txt`,
		`f=a.txt; readarray f; cp $f out.txt`,
		`f=a.txt; typeset f=-t; cp $f out.txt`,
		`f=a.txt; local f; cp $f out.txt`,
		`f=a.txt; readonly f; cp $f out.txt`,
		`f=a.txt; pushd build; cp $f out.txt`,
		`f=a.txt; popd; cp $f out.txt`,
		`f=a.txt; set -- x; cp $f out.txt`,
		`f=a.txt; shopt -s nullglob; cp $f out.txt`,
		`f=a.txt; alias cp=x; cp $f out.txt`,
		`f=a.txt; unset f; cp $f out.txt`,
		`f=a.txt; x=$(read f); cp $f out.txt`,
		`f=a.txt; cat <(read f); cp $f out.txt`,
		`f=a.txt; if true; then read f; fi; cp $f out.txt`,
		`f=a.txt; while false; do read f; done; cp $f out.txt`,
		`f=a.txt; case x in x) read f;; esac; cp $f out.txt`,
		`f=a.txt; (read f); cp $f out.txt`,
		`f=a.txt; { read f; }; cp $f out.txt`,
		`f=a.txt; cat <<EOF2
$(read f)
EOF2
cp $f out.txt`,
		// Words that are not one plain parameter.
		`f=a.txt; cp ${f[0]} out.txt`,
		`f=a.txt; cp ${f[@]} out.txt`,
		`f=a.txt; cp ${#f} out.txt`,
		`f=a.txt; cp ${f:0:1} out.txt`,
		`f=a.txt; cp ${f@Q} out.txt`,
		`f=a.txt; cp ${f^^} out.txt`,
		`f=a.txt; cp ${f%.txt} out.txt`,
		`f=a.txt; g=b; cp $f$g out.txt`,
		`f=a.txt; cp x$f out.txt`,
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
		if !knownWordParameterUses(command, file, home)[word] {
			t.Errorf("%s: copy source not read as one known word", command)
		}
	}
	for _, command := range unknown {
		file, word := source(t, command)
		if knownWordParameterUses(command, file, home)[word] {
			t.Errorf("%s: copy source read as one known word", command)
		}
	}
	if got := QuotedDynamicCopyDestinations(`f=a.txt; cp $f out.txt`, "/p", home); !slices.Equal(got, []string{"/p/out.txt"}) {
		t.Errorf("fixed destination of a known unquoted source = %v", got)
	}
}

// rel-1-0-2:GAP-0004 review: a command with no parameter word or no copy
// program leaves at the text gate, without a second walk.
func BenchmarkKnownWordParameterUses(b *testing.B) {
	const home = "/home/u"
	for _, command := range []string{
		`go test ./... > out.log; echo done > report.txt`,
		`for f in a.txt README.md; do cp $f build/; done; echo hi > report.txt`,
	} {
		file, _ := parseShell(command)
		b.Run(command[:8], func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				knownWordParameterUses(command, file, home)
			}
		})
	}
}

// rel-1-0-6:GAP-0235: only a name every binding gives the same plain value
// has a value; a name with two values, or any unknown binding, has none.
func TestCopyWordValueIsKnownOnlyWhenEveryBindingGivesTheSameValue(t *testing.T) {
	const home = "/home/u"
	rows := []struct {
		command, want string
	}{
		{`f=out.txt; cp a.txt $f`, "out.txt"},
		{`f=out.txt; cp a.txt "$f"`, "out.txt"},
		{`f=out.txt; f=out.txt; cp a.txt ${f}`, "out.txt"},
		{`for f in out.txt; do cp a.txt $f; done`, "out.txt"},
		{`for f in out.txt b.txt; do cp a.txt $f; done`, ""},
		{`f=out.txt; f=b.txt; cp a.txt $f`, ""},
		{`f=out.txt; command read f; cp a.txt $f`, ""},
		{`cp a.txt $f`, ""},
		{`f=-t; cp a.txt $f`, ""},
	}
	for _, row := range rows {
		file, ok := parseShell(row.command)
		if !ok {
			t.Fatalf("%s does not parse", row.command)
		}
		values := knownWordParameterValues(row.command, file, home)
		got := ""
		syntax.Walk(file, func(node syntax.Node) bool {
			if call, ok := node.(*syntax.CallExpr); ok && len(call.Args) == 3 {
				got = values[call.Args[2]]
			}
			return true
		})
		if got != row.want {
			t.Errorf("%s: destination value %q, want %q", row.command, got, row.want)
		}
	}
	if got := LiteralWriteOperands(`f=out.txt; cp a.txt $f`, "/p", home); !slices.Contains(got, "/p/out.txt") {
		t.Errorf("literal operands of a known destination word = %v", got)
	}
}

// BD-BATCH3a merge of rel-1-0-6:GAP-0235 (known copy words) with
// rel-1-0-6:GAP-0228 (brace operands of every writer): a cp call with a
// known parameter word and a brace word lists the keys file the brace word
// names, and the known word stays a copy-only reading (a tee operand named
// by a parameter keeps the GAP-2514 reader).
func TestKnownCopyWordNextToABraceOperand(t *testing.T) {
	const home = "/home/u"
	const keys = "/home/u/.ssh/authorized_keys"
	for _, command := range []string{
		`f=a.pub; cp $f {,"$HOME"/.ssh/authorized_keys}`,
		`f=a.pub; cp "$f" "$HOME"/.ssh/{,authorized_key"s"}`,
		`f=/home/u/.ssh/authorized_keys; cp {a,b}.pub $f`,
		`f=/home/u/.ssh/authorized_keys; tee $f {,out.txt}`,
	} {
		if got := LiteralWriteOperands(command, "/p", home); !slices.Contains(got, keys) {
			t.Errorf("%s: literal operands %v, want %s", command, got, keys)
		}
	}
	// An unknown parameter word keeps the cp call dynamic, as before.
	if got := LiteralWriteOperands(`cp $g {,"$HOME"/.ssh/authorized_keys}`, "/p", home); slices.Contains(got, keys) {
		t.Errorf("unknown copy word: literal operands %v list the keys file", got)
	}
}
