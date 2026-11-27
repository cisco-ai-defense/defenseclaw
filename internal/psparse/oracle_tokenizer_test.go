// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import (
	"bufio"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// oracleRow is one sample row of testdata/oracle_tokenizer_rows.tsv: a public
// script from the pwsh 7.6.6 oracle fixture (scripts/pwshoracle/fixture) and
// the command names the real parser reads in it and the parameters it binds a
// -Name: value to.
type oracleRow struct {
	class, id, src string
	names, colon   []string
}

func loadOracleRows(t *testing.T) []oracleRow {
	t.Helper()
	f, err := os.Open("testdata/oracle_tokenizer_rows.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var rows []oracleRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		ln := sc.Text()
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		c := strings.Split(ln, "\t")
		if len(c) != 5 {
			t.Fatalf("bad row %q", ln)
		}
		b, err := base64.StdEncoding.DecodeString(c[2])
		if err != nil {
			t.Fatalf("%s: %v", c[1], err)
		}
		var names []string
		if c[3] != "" {
			names = strings.Split(c[3], "|")
		}
		var colon []string
		if c[4] != "" {
			colon = strings.Split(c[4], "|")
		}
		rows = append(rows, oracleRow{class: c[0], id: c[1], src: string(b), names: names, colon: colon})
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return rows
}

// missingCommands returns the command names the real parser reads that the
// reader does not (multiset difference): the reader must never see less.
func missingCommands(src string, want []string) ([]string, []string) {
	sc, _ := Parse(src, Options{})
	got := map[string]int{}
	var gotNames []string
	if sc != nil {
		for _, inv := range Project(sc) {
			got[inv.Name]++
			gotNames = append(gotNames, inv.Name)
		}
	}
	var miss []string
	for _, w := range want {
		if got[w] > 0 {
			got[w]--
			continue
		}
		miss = append(miss, w)
	}
	return miss, gotNames
}

// TestOracleRowsSeeEveryCommand: for each sample row of a tokenizer class the
// reader sees every command pwsh 7.6.6 reads. Red at a64bfdb931 and at the
// det111/engine-train-2 tip for the classes below.
func TestOracleRowsSeeEveryCommand(t *testing.T) {
	rows := loadOracleRows(t)
	if len(rows) == 0 {
		t.Fatal("no rows")
	}
	for _, r := range rows {
		r := r
		t.Run(r.class+"/"+r.id, func(t *testing.T) {
			miss, got := missingCommands(r.src, r.names)
			if r.class == "gap1853" && len(miss) > 0 && len(miss) < len(r.names) && hasDepthLimit(r.src) {
				// nesting past the parse depth bound: the commands below it may
				// be unread, but only with a ps_depth_limit diagnostic
				return
			}
			if len(miss) > 0 {
				t.Errorf("reader misses %q (pwsh reads %q, reader %q)", miss, r.names, got)
			}
		})
	}
}

// TestGAP1850GluedHashIsWordText: a '#' glued to a word that continues through
// a quote is word text, not a comment, so the command after ';' is read; a '#'
// at a fresh token start (after a string that starts a token, ')' or an
// assignment in an expression statement) still starts a comment. Expected
// command names are what pwsh 7.6.6 reads (scripts/pwshoracle probe).
func TestGAP1850GluedHashIsWordText(t *testing.T) {
	cases := []struct {
		src  string
		want []string // command names, in order
	}{
		{`Write-Output a"b"#; Remove-Item -Recurse -Force C:\Users\alice\.defenseclaw`, []string{"write-output", "remove-item"}},
		{`Write-Output a'b'#; Remove-Item x`, []string{"write-output", "remove-item"}},
		{`Write-Output -Version"2"#; Remove-Item x`, []string{"write-output", "remove-item"}},
		{`Write-Output a"b"'c'#; Remove-Item x`, []string{"write-output", "remove-item"}},
		{`Write-Output a"b"<# c #>; Remove-Item x`, []string{"write-output"}}, // pwsh: a"b"<# is one word, then c, then the comment #>; ...
		{`Write-Output [int]#; Remove-Item x`, []string{"write-output", "remove-item"}},
		{`Get-ChildItem .\a[1]#; Remove-Item x`, []string{"get-childitem", "remove-item"}},
		{"$x =<# c #> Remove-Item x", []string{"remove-item"}},
		{"$x =# c\nRemove-Item y", []string{"remove-item"}},
		// comments pwsh also reads as comments
		{`Write-Output "b"#; Remove-Item x`, []string{"write-output"}},
		{`Write-Output (1)#; Remove-Item x`, []string{"write-output"}},
		{`Write-Output 'a' #; Remove-Item x`, []string{"write-output"}},
	}
	for _, c := range cases {
		sc, err := Parse(c.src, Options{})
		if err != nil {
			t.Fatalf("%q: %v", c.src, err)
		}
		var got []string
		for _, inv := range Project(sc) {
			got = append(got, inv.Name)
		}
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%q: commands %q, want %q", c.src, got, c.want)
		}
	}
}

// TestGAP1854ColonParamBindsDashWord: in the gap1854 sample rows pwsh 7.6.6
// binds the word after "-Name:" as its value even when it starts with "-"
// (-nop: -c:, -a:-b): the reader binds a value to every parameter the real
// parser does. Red at the det111/engine-train-2 tip.
func TestGAP1854ColonParamBindsDashWord(t *testing.T) {
	n := 0
	for _, r := range loadOracleRows(t) {
		if r.class != "gap1854" {
			continue
		}
		n++
		sc, _ := Parse(r.src, Options{})
		bound := map[string]int{}
		WalkCommands(sc, func(c *Command) {
			for _, el := range c.Elements {
				if p, ok := el.(*Parameter); ok && p.Colon != nil {
					bound[strings.ToLower(p.Name)]++
				}
			}
		})
		for _, w := range r.colon {
			if bound[w] == 0 {
				t.Errorf("%s: -%s: has no value (pwsh binds %q)", r.id, w, r.colon)
				continue
			}
			bound[w]--
		}
	}
	if n == 0 {
		t.Fatal("no gap1854 rows")
	}
}

// TestGAP1851BracketWordAndOperatorCommandWord: [ and ] are word characters
// in command mode (they never group and never cross a statement separator),
// and a word that starts with an operator character or "]" in command
// position is a command name; the unary operators still start an expression.
// Expected names are what pwsh 7.6.6 reads (scripts/pwshoracle probe).
func TestGAP1851BracketWordAndOperatorCommandWord(t *testing.T) {
	cases := []struct {
		src  string
		want []string
	}{
		{`Write-Output a[#; Remove-Item -Recurse -Force C:\`, []string{"write-output", "remove-item"}},
		{`Write-Output a[b; Remove-Item x`, []string{"write-output", "remove-item"}},
		{"Write-Output a[b\nRemove-Item x", []string{"write-output", "remove-item"}},
		{`Write-Output a[b | Remove-Item x`, []string{"write-output", "remove-item"}},
		{`Write-Output [b && Remove-Item x`, []string{"write-output", "remove-item"}},
		{`Write-Output a[$(b; c)]; Remove-Item x`, []string{"write-output", "b", "c", "remove-item"}},
		{`Write-Output a[1>2] y; Remove-Item x`, []string{"write-output", "remove-item"}},
		{`*** Begin x`, []string{"***"}},
		{`= x`, []string{"="}},
		{`] x`, []string{"]"}},
		{`]x y`, []string{"]x"}},
		{`?x y`, []string{"?x"}},
		{`*= x`, []string{"*="}},
		{`x; ?? y`, []string{"x", "??"}},
		{`(*** a)`, []string{"***"}},
		{`Write-Output a | *x b`, []string{"write-output", "*x"}},
		{`Write-Output a ] b; Remove-Item x`, []string{"write-output", "remove-item"}},
		{`$a[(Get-X)]; Remove-Item x`, []string{"get-x", "remove-item"}},
		{`! (Get-X)`, []string{"get-x"}},
	}
	for _, c := range cases {
		sc, _ := Parse(c.src, Options{})
		var got []string
		for _, inv := range Project(sc) {
			got = append(got, inv.Name)
		}
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%q: commands %q, want %q", c.src, got, c.want)
		}
	}
}

func hasDepthLimit(src string) bool {
	sc, _ := Parse(src, Options{})
	for _, d := range sc.Diagnostics {
		if d.Reason == ReasonDepthLimit {
			return true
		}
	}
	return false
}

// TestGAP1853NestedHereStringDepth: a "@ line inside a $( ) of an expandable
// here-string ends the nested here-string, not the outer one (pwsh counts $(
// and ) as in a "..." string), so every nested command is read; past the parse
// depth bound the reader emits ps_depth_limit and still reads the commands
// around the string. Red at the det111/engine-train-2 tip.
func TestGAP1853NestedHereStringDepth(t *testing.T) {
	nest := func(n int) string {
		s := "$(Get-X)"
		for i := 0; i < n; i++ {
			s = "$(@\"\n" + s + "\n\"@)"
		}
		return "Write-Output @\"\n" + s + "\n\"@; Remove-Item y"
	}
	for _, n := range []int{1, 3, 20} {
		src := nest(n)
		if miss, got := missingCommands(src, []string{"write-output", "get-x", "remove-item"}); len(miss) > 0 {
			t.Errorf("depth %d: reader misses %q (reader %q)", n, miss, got)
		}
		if hasDepthLimit(src) {
			t.Errorf("depth %d: unexpected ps_depth_limit", n)
		}
	}
	for _, n := range []int{maxDepth + 10, 999} {
		src := nest(n)
		if miss, got := missingCommands(src, []string{"write-output", "remove-item"}); len(miss) > 0 {
			t.Errorf("depth %d: reader misses %q (reader %d commands)", n, miss, len(got))
		}
		if !hasDepthLimit(src) {
			t.Errorf("depth %d: no ps_depth_limit diagnostic past the bound", n)
		}
	}
}
