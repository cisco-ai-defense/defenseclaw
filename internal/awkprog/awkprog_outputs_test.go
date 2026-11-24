// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package awkprog

import (
	"reflect"
	"testing"
)

// rel-1-0-10:GAP-1239: a print or printf statement that redirects into a
// file named by string literals lists the file; a > inside parentheses is a
// comparison, a > inside a string is data, and a target built from a field or
// a variable is not listed.
func TestParseOutputs(t *testing.T) {
	cases := []struct {
		name, program string
		want          []Output
	}{
		{"print truncate", `BEGIN{print "x" > "out.txt"}`, []Output{{Target: "out.txt"}}},
		{"print append", `{print $1 >> "log.txt"}`, []Output{{Target: "log.txt", Append: true}}},
		{"printf parens", `{printf("%s\n", $1) > "o.txt"}`, []Output{{Target: "o.txt"}}},
		{"bare print", `{print > "o.txt"}`, []Output{{Target: "o.txt", RecordInput: true}}},
		{"concatenated target", `BEGIN{print "x" > "/tmp/" "o.txt"}`, []Output{{Target: "/tmp/o.txt"}}},
		{"then close", `BEGIN{print "x" > "o.txt"; close("o.txt")}`, []Output{{Target: "o.txt"}}},
		{"two statements", "BEGIN{print 1 > \"a\"}\nEND{print 2 >> \"b\"}", []Output{{Target: "a"}, {Target: "b", Append: true}}},
		{"escaped target", `BEGIN{print "x" > "a\057b"}`, []Output{{Target: "a/b"}}},
		{"record print", `{print $0 > "o.txt"}`, []Output{{Target: "o.txt", RecordInput: true}}},
		{"record printf", `{printf "%s", $0 >> "o.txt"}`, []Output{{Target: "o.txt", Append: true, RecordInput: true}}},
		{"conditioned print", `$1 == 1 {print > "o.txt"}`, []Output{{Target: "o.txt"}}},
		{"begin print", `BEGIN{print > "o.txt"}`, []Output{{Target: "o.txt"}}},
		{"second statement", `{print > "o.txt"; print "x"}`, []Output{{Target: "o.txt"}}},
		{"comparison in parens", `{print ($1 > 2)}`, nil},
		{"comparison outside print", `{if ($1 > 2) print}`, nil},
		{"greater in a string", `{print "a > b"}`, nil},
		{"field target", `{print > $1}`, nil},
		{"computed target", `{print > ($1 ".txt")}`, nil},
		{"variable target", `{print > f}`, nil},
		{"empty target", `{print > ""}`, nil},
		{"pipe", `{print | "sort"}`, nil},
	}
	for _, c := range cases {
		if got := Parse(c.program).Outputs; !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: outputs %+v, want %+v", c.name, got, c.want)
		}
	}
}

// rel-1-0-10:GAP-1239: the reading of a call writes each print redirect as
// the shell redirect of the same file, the target single-quoted as the
// literal awk opens, next to the commands the program starts; a call with no
// command channel and no literal output has no body. A redirect starts no
// command (Starts, rel-1-0-10:GAP-1566).
func TestReadWritesPrintRedirects(t *testing.T) {
	cases := []struct {
		words  []string
		body   string
		starts bool
	}{
		{[]string{"awk", `BEGIN{print "x" > "/s/config.yaml"}`}, `: > '/s/config.yaml'`, false},
		{[]string{"awk", `{print >> "~/a'b"}`, "in.txt"}, `: >> '~/a'\''b'`, false},
		{[]string{"gawk", "-e", `BEGIN{system("ls"); print 1 > "o"}`}, "( ls\n)\n( : > 'o'\n)", true},
		{[]string{"awk", `BEGIN{print 1 > "o"; print 2 | "sort"}`}, "( sort\n)\n( : > 'o'\n)", true},
		{[]string{"awk", `{print $1}`, "in.txt"}, "", false},
		{[]string{"awk", `{print > $1}`, "in.txt"}, "", false},
	}
	for _, c := range cases {
		if got := (Call{Words: c.words}).Read(); got.Body != c.body || got.Dynamic || got.Starts != c.starts {
			t.Errorf("%q: body %q dynamic %v starts %v, want %q static starts %v", c.words, got.Body, got.Dynamic, got.Starts, c.body, c.starts)
		}
	}
	// A program with a shell hole: an output whose target holds the hole is
	// not known and is left out; a literal output is still written.
	holed := Call{Words: []string{"awk", "x"}, Dynamic: []bool{false, true},
		Holed: []string{"", `BEGIN{print "x" > "` + Hole + `"; print "y" > "lit"}`}}
	if got := holed.Read(); got.Body != `: > 'lit'` || !got.Dynamic || got.Starts {
		t.Errorf("holed program: body %q dynamic %v starts %v, want the literal output, dynamic, no command", got.Body, got.Dynamic, got.Starts)
	}
}
