// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import (
	"bufio"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// gap1854FixtureDir is the pwsh 7.6.6 oracle fixture (scripts/pwshoracle).
const gap1854FixtureDir = "../../scripts/pwshoracle/fixture"

// gap1854Classes are the word classes of rel-1-0-10:GAP-1854 besides
// -Name: value (TestGAP1854ColonParamBindsDashWord), each with the fixture
// rows the gap names. The quoted '--%' class is not here: pwsh drops the
// words after it from the AST, the reader keeps them.
var gap1854Classes = map[string][]string{
	// -Version'2' is the bareword -Version2, -ep' x' is "-ep x"
	"glued-quote": {"pw-0032346234", "pw-004ffad7ec", "pw-007f0187e5"},
	// -nop-ExecutionPolicy and -ep/c are one parameter name each
	"parameter-name": {"pw-04bd330665", "pw-0515586852"},
	// a standalone -- is the parameter "-" (also after a string or a
	// number); a -word after it is an argument
	"double-dash": {"pw-0e40c5976d", "pw-b36050e623", "pw-b541f02a65"},
	// a quoted piece of a fused word keeps its inner quotes and a doubled
	// quote is its second quote char (--command:'say "hi"' = --command:say "hi")
	"fused-quotes": {"pw-0036673b67", "pw-00a3f4857e", "pw-0293f1bd87", "pw-35501afe63"},
}

// gap1854Row is one fixture row: its script and the elements of its first
// command as the real parser reads them (oracle view: ["param", name, ...]
// or [kind, value, static]).
type gap1854Row struct {
	src string
	el  [][]any
}

func loadGAP1854Rows(t *testing.T, want map[string]bool) map[string]gap1854Row {
	t.Helper()
	idf, err := os.Open(gap1854FixtureDir + "/pub.ids")
	if err != nil {
		t.Fatal(err)
	}
	defer idf.Close()
	index := map[int]string{}
	sc := bufio.NewScanner(idf)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for i := 0; sc.Scan(); i++ {
		if id, _, _ := strings.Cut(sc.Text(), "\t"); want[id] {
			index[i] = id
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	rows := map[string]gap1854Row{}
	gzLines(t, gap1854FixtureDir+"/pub.b64.gz", func(i int, line string) {
		if id, ok := index[i]; ok {
			b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
			if err != nil {
				t.Fatalf("%s: %v", id, err)
			}
			rows[id] = gap1854Row{src: string(b)}
		}
	})
	gzLines(t, gap1854FixtureDir+"/pub.oview.jsonl.gz", func(_ int, line string) {
		var v struct {
			I    int `json:"i"`
			Cmds []struct {
				El [][]any `json:"el"`
			} `json:"cmds"`
		}
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Fatal(err)
		}
		if id, ok := index[v.I]; ok && len(v.Cmds) > 0 {
			r := rows[id]
			r.el = v.Cmds[0].El
			rows[id] = r
		}
	})
	return rows
}

func gzLines(t *testing.T, path string, each func(int, string)) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 1<<20), 1<<26)
	for i := 0; sc.Scan(); i++ {
		each(i, sc.Text())
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
}

// gap1854Word is one command element as the test compares it: a parameter
// name, or an argument value (empty when the value is not a static string).
type gap1854Word struct {
	param bool
	text  string
}

func gap1854OracleWords(el [][]any) []gap1854Word {
	var out []gap1854Word
	for _, e := range el {
		kind, _ := e[0].(string)
		text, _ := e[1].(string)
		switch kind {
		case "param":
			out = append(out, gap1854Word{param: true, text: strings.ToLower(text)})
		case "bare", "sq", "dq":
			out = append(out, gap1854Word{text: text})
		default:
			out = append(out, gap1854Word{})
		}
	}
	return out
}

func gap1854ReaderWords(c *Command) []gap1854Word {
	var out []gap1854Word
	for _, el := range c.Elements {
		switch v := el.(type) {
		case *Parameter:
			out = append(out, gap1854Word{param: true, text: strings.ToLower(v.Name)})
		case *Arg:
			w := gap1854Word{}
			if s, ok := v.Value.(*StringLit); ok && s.Static {
				w.text = s.Value
			}
			out = append(out, w)
		default:
			out = append(out, gap1854Word{text: "?"})
		}
	}
	return out
}

// TestGAP1854WordClassesMatchTheRealParser: for every class of the gap the
// reader's parameters and argument values of the named fixture rows equal
// pwsh 7.6.6's. Red at 5e93cafe74 for each class.
func TestGAP1854WordClassesMatchTheRealParser(t *testing.T) {
	want := map[string]bool{}
	for _, ids := range gap1854Classes {
		for _, id := range ids {
			want[id] = true
		}
	}
	rows := loadGAP1854Rows(t, want)
	for class, ids := range gap1854Classes {
		for _, id := range ids {
			t.Run(class+"/"+id, func(t *testing.T) {
				r, ok := rows[id]
				if !ok || r.el == nil {
					t.Fatalf("row %s is not in the fixture", id)
				}
				sc, _ := Parse(r.src, Options{})
				var first *Command
				WalkCommands(sc, func(c *Command) {
					if first == nil {
						first = c
					}
				})
				if first == nil {
					t.Fatalf("%q: no command", r.src)
				}
				got, exp := gap1854ReaderWords(first), gap1854OracleWords(r.el)
				if len(got) != len(exp) {
					t.Fatalf("%q: reader reads %d elements %+v, pwsh %d %+v", r.src, len(got), got, len(exp), exp)
				}
				for i := range exp {
					if got[i].param != exp[i].param || (exp[i].text != "" && got[i].text != exp[i].text) {
						t.Errorf("%q element %d: reader %+v, pwsh %+v", r.src, i, got[i], exp[i])
					}
				}
			})
		}
	}
}

// TestGAP1854GluedNameKeepsItsColon: a glued -b: ends the glued name with its
// colon, and its value binds as for any -Name: value.
func TestGAP1854GluedNameKeepsItsColon(t *testing.T) {
	sc, _ := Parse("Get-Thing -a-b:c d", Options{})
	var got []gap1854Word
	WalkCommands(sc, func(c *Command) {
		if got == nil {
			got = gap1854ReaderWords(c)
			for _, el := range c.Elements {
				if p, ok := el.(*Parameter); ok && (!p.HasColon || p.Colon == nil) {
					t.Errorf("-%s: has no colon value", p.Name)
				}
			}
		}
	})
	want := []gap1854Word{{param: true, text: "a-b"}, {text: "d"}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("reader %+v, want %+v", got, want)
	}
}
