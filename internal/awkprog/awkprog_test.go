// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package awkprog

import (
	"reflect"
	"strings"
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
		"open string with a call": `BEGIN{system("x}`,
		"open regex with a pipe":  `/a | getline`,
		"gawk directive":          `@include "x.awk"`,
	} {
		p := Parse(program)
		if _, dynamic := p.Commands(); !dynamic || !p.RunsCommand() {
			t.Errorf("%s: %+v is read as a program with no command", name, p)
		}
	}
}

// Every awk refuses a program whose literal has no end, and runs nothing; with
// no word or pipe in its text that starts a command it is not an unknown
// command (an unquoted regex word in a shell line is one), though the older
// readers still count it as a command effect.
func TestParseMalformedProgramWithNoChannelTextIsNotDynamic(t *testing.T) {
	for name, program := range map[string]string{
		"open regex":  `/Prompt`,
		"open string": `BEGIN{print "x}`,
	} {
		p := Parse(program)
		if _, dynamic := p.Commands(); dynamic {
			t.Errorf("%s: read as an unknown command", name)
		}
		if !p.RunsCommand() {
			t.Errorf("%s: RunsCommand dropped the malformed program", name)
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
		got, dynamic := commandsOf(Call{Words: tc.argv})
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

func TestReadIsDynamicForAnUnreadableCommand(t *testing.T) {
	if reading := (Call{Words: []string{"awk", `BEGIN{system("echo (")}`}}).Read(); !reading.Dynamic {
		t.Error("a command the shell reader cannot parse is read as fully known")
	}
	if reading := (Call{Words: []string{"awk", `BEGIN{system("true")}`}}).Read(); reading.Body != "true" || reading.Dynamic {
		t.Errorf("literal command: %+v", reading)
	}
}

// commandsOf is the static commands the programs of a call run, and whether
// the call runs a command or a program it cannot read.
func commandsOf(call Call) (commands []string, dynamic bool) {
	commands, reading := call.commands()
	return commands, reading.Dynamic
}

// rel-1-0-10:GAP-0654: awk tells a regular expression from a division by the
// previous significant token. The scan must agree, or a regular expression
// literal with a quote in it hides the command that follows, or a division
// swallows one.
func TestSlashIsReadByThePreviousToken(t *testing.T) {
	regexAfter := []string{"+", "-", "*", "%", "^", "<", ">", "==", "!=", "<=", ">=", "&&", "||", "!", "~", "!~", "?", ":", ",", "=", "+=", "(", "{", ";", "|", "&"}
	for _, operator := range regexAfter {
		program := `BEGIN{ y = 1 ` + operator + ` /"/; system("a"); y = 1 ` + operator + ` /"/ }`
		if got, _ := commandsOf(Call{Words: []string{"awk", program}}); !reflect.DeepEqual(got, []string{"a"}) {
			t.Errorf("a regular expression after %q: commands %q, want [a]", operator, got)
		}
	}
	programs := map[string]string{
		"if header":                     `BEGIN{ if (1) /"/; system("a"); if (1) /"/ }`,
		"while header":                  `BEGIN{ while (0) /"/; system("a"); while (0) /"/ }`,
		"for header":                    `BEGIN{ for (;0;) /"/; system("a"); for (;0;) /"/ }`,
		"newline":                       "BEGIN{ x = 1\n/\"/ ; system(\"a\") ; y\n/\"/ }",
		"division by a name":            `BEGIN{ x = a / 2; y = b / 3; system("a") }`,
		"division by a number":          `BEGIN{ x = 4 / 2; y = 6 / 3; system("a") }`,
		"division after a paren":        `BEGIN{ x = (a) / 2; y = (b) / 3; system("a") }`,
		"division after a call":         `BEGIN{ x = length(a) / 2; y = length(b) / 3; system("a") }`,
		"division after a bracket":      `BEGIN{ x = a[1] / 2; y = b[1] / 3; system("a") }`,
		"division after postfix":        `BEGIN{ x = i++ / 2; y = j++ / 3; system("a") }`,
		"division after a string":       `BEGIN{ x = "a" / 2; y = "b" / 3; system("a") }`,
		"division after a field":        `{ x = $1 / 2; y = $2 / 3; system("a") }`,
		"regex after print":             `{ print /"/; system("a"); print /"/ }`,
		"regex after a header, newline": "{ if (1)\n/\"/; system(\"a\"); if (1)\n/\"/ }",
	}
	for name, program := range programs {
		if got, _ := commandsOf(Call{Words: []string{"awk", program}}); !reflect.DeepEqual(got, []string{"a"}) {
			t.Errorf("%s: commands %q, want [a]", name, got)
		}
	}
}

func TestCallReadsProgramFilesAndComputedWords(t *testing.T) {
	files := map[string]string{
		"p.awk":    `BEGIN{system("a")}`,
		"pipe.awk": `{print | "b"}`,
		"dyn.awk":  `{system($1)}`,
		"none.awk": `{print $1}`,
	}
	read := func(name string) (string, bool) { text, ok := files[name]; return text, ok }
	type tc struct {
		name    string
		words   []string
		dynamic []bool
		prefix  []string
		holed   []string
		files   FileReader
		want    []string
		unknown bool
		unread  bool
	}
	cases := []tc{
		{name: "-f", words: []string{"awk", "-f", "p.awk", "in"}, files: read, want: []string{"a"}},
		{name: "-f attached", words: []string{"awk", "-fp.awk"}, files: read, want: []string{"a"}},
		{name: "--file=", words: []string{"gawk", "--file=p.awk"}, files: read, want: []string{"a"}},
		{name: "-E", words: []string{"gawk", "-E", "p.awk", "x"}, files: read, want: []string{"a"}},
		{name: "--exec", words: []string{"gawk", "--exec", "p.awk"}, files: read, want: []string{"a"}},
		{name: "--exec=", words: []string{"gawk", "--exec=p.awk"}, files: read, want: []string{"a"}},
		{name: "-W exec", words: []string{"mawk", "-W", "exec", "p.awk"}, files: read, want: []string{"a"}},
		{name: "-Wexec", words: []string{"mawk", "-Wexec", "p.awk"}, files: read, want: []string{"a"}},
		{name: "two files", words: []string{"awk", "-f", "p.awk", "-f", "pipe.awk"}, files: read, want: []string{"a", "b"}},
		{name: "file and operand", words: []string{"awk", "-f", "none.awk", "p.awk"}, files: read},
		{name: "a file with a computed command", words: []string{"awk", "-f", "dyn.awk"}, files: read, unknown: true},
		{name: "a file that cannot be read", words: []string{"awk", "-f", "missing.awk"}, files: read, unknown: true, unread: true},
		{name: "stdin as the file", words: []string{"awk", "-f", "-"}, files: read, unknown: true, unread: true},
		{name: "a computed file name", words: []string{"awk", "-f", ""}, dynamic: []bool{false, false, true}, files: read, unknown: true, unread: true},
		{name: "no reach is not unknown", words: []string{"awk", "-f", "p.awk"}},
		{name: "-W other", words: []string{"mawk", "-W", "version", `BEGIN{system("c")}`}, files: read, want: []string{"c"}},
		{name: "computed program", words: []string{"awk", ""}, dynamic: []bool{false, true}, unknown: true},
		{name: "computed program with a command in its text", words: []string{"awk", ""}, dynamic: []bool{false, true}, holed: []string{"", `BEGIN{system("d"); x = ` + Hole + `}`}, want: []string{"d"}, unknown: true},
		{name: "computed program, a command with a hole", words: []string{"awk", ""}, dynamic: []bool{false, true}, holed: []string{"", `BEGIN{system("touch ` + Hole + `")}`}, unknown: true},
		{name: "computed program with no command text", words: []string{"awk", ""}, dynamic: []bool{false, true}, holed: []string{"", Hole + `==3 || ` + Hole + `==4 {print}`}},
		{name: "computed program, one hole", words: []string{"awk", ""}, dynamic: []bool{false, true}, holed: []string{"", Hole}, unknown: true},
		{name: "computed program, a pipe", words: []string{"awk", ""}, dynamic: []bool{false, true}, holed: []string{"", `{print ` + Hole + ` | "sort"}`}, want: []string{"sort"}, unknown: true},
		{name: "computed input operand", words: []string{"awk", `{print $1}`, ""}, dynamic: []bool{false, false, true}},
		{name: "computed -v value", words: []string{"awk", "-v", "", `BEGIN{system(c)}`}, dynamic: []bool{false, false, true, false}, unknown: true},
		{name: "computed -F value", words: []string{"awk", "-F", "", `{print $1}`}, dynamic: []bool{false, false, true, false}},
		{name: "computed attached -F", words: []string{"awk", "-F", `{print $1}`}, dynamic: []bool{false, true, false}, prefix: []string{"", "-F"}},
		{name: "computed attached -f", words: []string{"awk", ""}, dynamic: []bool{false, true}, prefix: []string{"", "-f"}, files: read, unknown: true, unread: true},
		{name: "computed -e", words: []string{"awk", "-e", ""}, dynamic: []bool{false, false, true}, unknown: true},
		{name: "computed option", words: []string{"awk", "", `{print}`}, dynamic: []bool{false, true, false}, unknown: true},
		{name: "static program with a computed operand", words: []string{"awk", `BEGIN{system("a")}`, ""}, dynamic: []bool{false, false, true}, want: []string{"a"}},
		{name: "program with a computed command", words: []string{"awk", `BEGIN{system(c)}`}, unknown: true},
	}
	for _, tc := range cases {
		call := Call{Words: tc.words, Dynamic: tc.dynamic, Prefix: tc.prefix, Holed: tc.holed, Files: tc.files}
		got, dynamic := commandsOf(call)
		if !reflect.DeepEqual(got, tc.want) || dynamic != tc.unknown {
			t.Errorf("%s: commands %q unknown %v, want %q %v", tc.name, got, dynamic, tc.want, tc.unknown)
		}
		if reading := call.Read(); reading.Unread != tc.unread || reading.Dynamic != tc.unknown {
			t.Errorf("%s: Read %+v, want unread %v dynamic %v", tc.name, reading, tc.unread, tc.unknown)
		}
	}
}

// The one bound rule: a program past MaxProgramBytes is read to the cap and
// reported Truncated, so a flood of tokens costs a bounded scan and is never
// an allow.
func TestParseCutsAProgramPastTheByteCap(t *testing.T) {
	flood := strings.Repeat("print ", 100000)
	program := Parse(flood)
	if !program.Truncated || !program.RunsCommand() {
		t.Fatalf("a %d byte program is not truncated: %+v", len(flood), program.Truncated)
	}
	if _, dynamic := program.Commands(); !dynamic {
		t.Error("a truncated program is read as fully known")
	}
	if Parse(`BEGIN{system("a")}`+strings.Repeat(" ", MaxProgramBytes)).Truncated == false {
		t.Error("a program with trailing blanks past the cap is not truncated")
	}
	// What is read before the cap still decides.
	if got, _ := Parse(`BEGIN{system("a")}` + strings.Repeat("x", MaxProgramBytes)).Commands(); !reflect.DeepEqual(got, []string{"a"}) {
		t.Errorf("the command before the cap was lost: %q", got)
	}
	if reading := (Call{Words: []string{"awk", flood}}).Read(); !reading.Truncated || !reading.Dynamic {
		t.Errorf("Read of a truncated program: %+v", reading)
	}
}
