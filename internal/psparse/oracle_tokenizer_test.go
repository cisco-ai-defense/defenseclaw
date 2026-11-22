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
// the command names the real parser reads in it.
type oracleRow struct {
	class, id, src string
	names          []string
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
		if len(c) != 4 {
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
		rows = append(rows, oracleRow{class: c[0], id: c[1], src: string(b), names: names})
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
			if miss, got := missingCommands(r.src, r.names); len(miss) > 0 {
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
