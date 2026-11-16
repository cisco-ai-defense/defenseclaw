// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

func declOf(t *testing.T, command string) *syntax.DeclClause {
	t.Helper()
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil || len(file.Stmts) != 1 {
		t.Fatalf("parse %q: %v", command, err)
	}
	decl, ok := file.Stmts[0].Cmd.(*syntax.DeclClause)
	if !ok {
		t.Fatalf("%q is no declaration", command)
	}
	return decl
}

// rel-1-0-6:GAP-0880, GAP-0885 round 11: every reader of a declaration option
// shares one scan. The options are the words in front of the first name, up to
// and with --; a later word is a stray (bash sets the name and reports it).
func TestSimpleDeclOptionsEndAtTheFirstName(t *testing.T) {
	for _, row := range []struct {
		command         string
		options, strays []string
		global          bool
	}{
		{"declare -g d=x", []string{"-g"}, nil, true},
		{"declare d=x -g", nil, []string{"-g"}, false},
		{"typeset d=x -g", nil, []string{"-g"}, false},
		{"declare -x -g d=x", []string{"-x", "-g"}, nil, true},
		{"declare -xg d=x", []string{"-xg"}, nil, true},
		{"declare -p IFS=x", []string{"-p"}, nil, false},
		{"declare IFS=x -p", nil, []string{"-p"}, false},
		{"declare -- d=x -g", []string{"--"}, []string{"-g"}, false},
		{"declare -r d=x -g e=y", []string{"-r"}, []string{"-g"}, false},
		{"declare d", nil, nil, false},
	} {
		options, strays := simpleDeclOptions(declOf(t, row.command))
		var gotOptions, gotStrays []string
		for _, option := range options {
			gotOptions = append(gotOptions, option.Value)
		}
		for _, stray := range strays {
			gotStrays = append(gotStrays, stray.Value)
		}
		if !slices.Equal(gotOptions, row.options) || !slices.Equal(gotStrays, row.strays) {
			t.Errorf("%q: options %q strays %q, want %q and %q", row.command, gotOptions, gotStrays, row.options, row.strays)
		}
		if got := simpleDeclGlobal(declOf(t, row.command)); got != row.global {
			t.Errorf("%q: global = %v, want %v", row.command, got, row.global)
		}
	}
}

// A declare or typeset in a function makes the name local unless -g is given
// before the first name: with the -g after it, the caller keeps its value.
func TestSimpleCommandsDeclareOptionAfterAnAssignmentLeavesTheCallersValue(t *testing.T) {
	const kept = "sed -i x \x27/r/home/.defenseclaw/config.yaml\x27"
	const replaced = "sed -i x \x27/r/home/ordinary/config.yaml\x27"
	for _, row := range []struct {
		name, command  string
		kept, replaced bool
	}{
		{"declare late -g", "d=.defenseclaw; f() { declare d=ordinary -g; }; f; sed -i x /r/home/$d/config.yaml", true, false},
		{"typeset late -g", "d=.defenseclaw; f() { typeset d=ordinary -g; }; f; sed -i x /r/home/$d/config.yaml", true, false},
		{"declare leading -g", "d=.defenseclaw; f() { declare -g d=ordinary; }; f; sed -i x /r/home/$d/config.yaml", false, true},
		{"declare -xg", "d=.defenseclaw; f() { declare -xg d=ordinary; }; f; sed -i x /r/home/$d/config.yaml", false, true},
		{"declare after --", "d=.defenseclaw; f() { declare -- d=ordinary -g; }; f; sed -i x /r/home/$d/config.yaml", true, false},
	} {
		for _, straight := range []bool{true, false} {
			t.Run(row.name, func(t *testing.T) {
				got := simpleTextsOf(t, row.command, straight)
				if has := slices.Contains(got, kept); has != row.kept {
					t.Errorf("straight=%v %q: caller value = %v, want %v (%q)", straight, row.command, has, row.kept, got)
				}
				if has := slices.Contains(got, replaced); has != row.replaced {
					t.Errorf("straight=%v %q: assigned value = %v, want %v (%q)", straight, row.command, has, row.replaced, got)
				}
			})
		}
	}
}

// The straight-line reading can differ from the whole-script reading only when
// the script declares a function or spells IFS; the syntax tree says so for
// every spelling the parser accepts.
func TestStraightLineReadingDiffersIsDecidedByTheSyntaxTree(t *testing.T) {
	for _, row := range []struct {
		command string
		differs bool
	}{
		{"f() { :; }; f", true},
		{"f ( ) { :; }; f", true},
		{"function f { :; }; f", true},
		{"function\tf { :; }; f", true},
		{"function f() { :; }; f", true},
		{"f()\n{\n:\n}\nf", true},
		{"IFS=x; ls", true},
		{"declare IFS=x; ls", true},
		{"declare I\"F\"S=x; ls", true},
		{"read -r IFS <<< x", true},
		{"echo ${IFS:=x}", true},
		{"( IFS=x; ls )", true},
		{"ls", false},
		{"cd x && make", false},
		{"echo \"$HOME\"/x", false},
		{"for x in a b; do echo $x; done", false},
		{"(cd x; ls)", false},
		{"arr=(a b); echo ${arr[0]}", false},
		{"v=$(echo hi); echo $v", false},
		{"cp a.txt IFSX.txt", false},
	} {
		file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(row.command), "")
		if err != nil {
			t.Fatalf("parse %q: %v", row.command, err)
		}
		if got := StraightLineReadingDiffers(file); got != row.differs {
			t.Errorf("%q: differs = %v, want %v", row.command, got, row.differs)
		}
	}
}
