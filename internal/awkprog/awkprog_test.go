// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package awkprog

import (
	"reflect"
	"testing"
)

func TestParseChannels(t *testing.T) {
	cases := []struct {
		name, program string
		commands      []string
		dynamic       bool
		kinds         []Kind
	}{
		{"system literal", `BEGIN{system("touch a")}`, []string{"touch a"}, false, []Kind{System}},
		{"system spaced", `BEGIN{system ("touch a")}`, []string{"touch a"}, false, []Kind{System}},
		{"system concatenation", `BEGIN{system("touch " "a")}`, []string{"touch a"}, false, []Kind{System}},
		{"system grouped", `BEGIN{system(("touch ") ("a"))}`, []string{"touch a"}, false, []Kind{System}},
		{"system escapes", `BEGIN{system("ls\057tmp \"x\"")}`, []string{`ls/tmp "x"`}, false, []Kind{System}},
		{"system field", `{system($1)}`, nil, true, []Kind{System}},
		{"system variable part", `{system("touch " f)}`, nil, true, []Kind{System}},
		{"system number part", `{system("sleep " 1)}`, nil, true, []Kind{System}},
		{"system bare", `{x = system}`, nil, true, []Kind{System}},
		{"print pipe", `{print $1 | "sort"}`, []string{"sort"}, false, []Kind{PrintPipe}},
		{"print pipe concatenated", `{print | "sort " "-n"}`, []string{"sort -n"}, false, []Kind{PrintPipe}},
		{"printf parens", `{printf("%s\n", $1) | "wc -l"}`, []string{"wc -l"}, false, []Kind{PrintPipe}},
		{"print pipe variable", `{print $1 | cmd}`, nil, true, []Kind{PrintPipe}},
		{"print pipe computed", `{print $1 | "sort " $2}`, nil, true, []Kind{PrintPipe}},
		{"print pipe coprocess", `{print |& "cat"}`, []string{"cat"}, false, []Kind{PrintPipe}},
		{"print pipe then close", `{print $1 | "sort"; close("sort")}`, []string{"sort"}, false, []Kind{PrintPipe}},
		{"two print pipes", "{print | \"a\"}\nEND{print | \"b\"}", []string{"a", "b"}, false, []Kind{PrintPipe, PrintPipe}},
		{"getline literal", `BEGIN{"date" | getline x}`, []string{"date"}, false, []Kind{GetlinePipe}},
		{"getline loop", `BEGIN{while (("ls" | getline l) > 0) n++}`, []string{"ls"}, false, []Kind{GetlinePipe}},
		{"getline assigned", `BEGIN{r = "ls" | getline}`, []string{"ls"}, false, []Kind{GetlinePipe}},
		{"getline grouped", `BEGIN{("ls " "-a") | getline x}`, []string{"ls -a", "ls -a"}, false, []Kind{GetlinePipe}},
		{"getline concatenation", `BEGIN{"echo " "x" | getline y}`, []string{"echo x", "x"}, false, []Kind{GetlinePipe}},
		{"getline variable", `BEGIN{cmd | getline x}`, nil, true, []Kind{GetlinePipe}},
		{"getline variable then literal", `BEGIN{cmd "ls" | getline x}`, []string{"ls"}, true, []Kind{GetlinePipe}},
		{"getline arithmetic", `BEGIN{1 + "ls" | getline x}`, []string{"ls"}, true, []Kind{GetlinePipe}},
		{"getline coprocess", `BEGIN{"ls" |& getline x}`, []string{"ls"}, false, []Kind{GetlinePipe}},
		{"mixed", `BEGIN{system("a"); print | "b"; "c" | getline x}`, []string{"a", "b", "c"}, false, []Kind{System, PrintPipe, GetlinePipe}},
		{"stray pipe", `{x | y}`, nil, true, []Kind{PrintPipe}},
		{"columns", `{print $1, $2}`, nil, false, nil},
		{"print to a file", `{print $1 > "out.txt"}`, nil, false, nil},
		{"regex with a pipe", `/a|b/ {print}`, nil, false, nil},
		{"match with a pipe", `$1 ~ "a|b" {print}`, nil, false, nil},
		{"logical or", `{if ($1 || $2) print "x|y"}`, nil, false, nil},
		{"string holds the call", `{print "system(\"x\")"}`, nil, false, nil},
		{"comment holds the call", "{print} # system(\"x\") | getline\n", nil, false, nil},
		{"function named like it", `{systemx = 1; print system_total}`, nil, false, nil},
		{"division then regex", `{x = a / b / c; print x}`, nil, false, nil},
		{"regex after print", `{print /a|b/ ? "y" : "n"}`, nil, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := Parse(tc.program)
			commands, dynamic := p.Commands()
			if !reflect.DeepEqual(commands, tc.commands) || dynamic != tc.dynamic {
				t.Fatalf("commands %q dynamic %v, want %q %v (%+v)", commands, dynamic, tc.commands, tc.dynamic, p)
			}
			var kinds []Kind
			for _, c := range p.Channels {
				kinds = append(kinds, c.Kind)
			}
			if !reflect.DeepEqual(kinds, tc.kinds) {
				t.Fatalf("kinds %v, want %v", kinds, tc.kinds)
			}
			if got := p.RunsCommand(); got != (len(tc.kinds) > 0) {
				t.Fatalf("RunsCommand %v", got)
			}
		})
	}
}

func TestParseUnreadableProgramsAreDynamic(t *testing.T) {
	for name, program := range map[string]string{
		"open string":    `BEGIN{print "x}`,
		"open regex":     `/a`,
		"gawk directive": `@include "x.awk"`,
	} {
		p := Parse(program)
		if _, dynamic := p.Commands(); !dynamic || !p.RunsCommand() {
			t.Errorf("%s: %+v is read as a program with no command", name, p)
		}
	}
}

func TestArgvPrograms(t *testing.T) {
	cases := []struct {
		name    string
		argv    []string
		want    []string
		dynamic bool
	}{
		{"program operand", []string{"awk", `BEGIN{system("a")}`, "f"}, []string{"a"}, false},
		{"options first", []string{"gawk", "-F:", "-v", "x=1", `{print | "sort"}`, "f"}, []string{"sort"}, false},
		{"program after --", []string{"mawk", "--", `BEGIN{system("a")}`}, []string{"a"}, false},
		{"source option", []string{"awk", "-e", `BEGIN{system("a")}`, "-e", `END{"b" | getline}`}, []string{"a", "b"}, false},
		{"operands are data", []string{"awk", `{print}`, `system("a")`, "x=system(b)"}, nil, false},
		{"value options are data", []string{"awk", "-v", `x=system("a")`, "-F", "|", `{print}`}, nil, false},
		{"program file", []string{"awk", "-f", "prog.awk", "f"}, nil, false},
		{"unknown option reads every word", []string{"awk", "-W", "x", `BEGIN{system("a")}`}, []string{"a"}, false},
		{"dynamic", []string{"awk", `{system($0)}`}, nil, true},
		{"none", []string{"awk"}, nil, false},
	}
	for _, tc := range cases {
		got, dynamic := ProgramsCommands(ArgvPrograms(tc.argv))
		if !reflect.DeepEqual(got, tc.want) || dynamic != tc.dynamic {
			t.Errorf("%s: %q %v, want %q %v", tc.name, got, dynamic, tc.want, tc.dynamic)
		}
	}
}

func TestShellBody(t *testing.T) {
	cases := []struct {
		name     string
		commands []string
		body     string
		unread   bool
	}{
		{"none", nil, "", false},
		{"blank is skipped", []string{" ", ""}, "", false},
		{"one is itself", []string{"touch a"}, "touch a", false},
		{"two are subshells", []string{"cd x", "touch a"}, "( cd x\n)\n( touch a\n)", false},
		{"comment cannot swallow the close", []string{"a # b", "c"}, "( a # b\n)\n( c\n)", false},
		{"unparsable is dropped and reported", []string{"echo (", "touch a"}, "touch a", true},
		{"only unparsable", []string{"echo ("}, "", true},
	}
	for _, tc := range cases {
		body, unread := ShellBody(tc.commands)
		if body != tc.body || unread != tc.unread {
			t.Errorf("%s: %q %v, want %q %v", tc.name, body, unread, tc.body, tc.unread)
		}
	}
}

func TestArgvShellIsDynamicForAnUnreadableCommand(t *testing.T) {
	if _, dynamic := ArgvShell([]string{"awk", `BEGIN{system("echo (")}`}); !dynamic {
		t.Error("a command the shell reader cannot parse is read as fully known")
	}
	if body, dynamic := ArgvShell([]string{"awk", `BEGIN{system("true")}`}); body != "true" || dynamic {
		t.Errorf("literal command: %q %v", body, dynamic)
	}
}
