// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestPerlSpecStageTwo(t *testing.T) {
	cases := []struct {
		id, code  string
		rel, spec []string
	}{
		{"P01 W2 rel union", "open(my $f, '>', 'p');", []string{"p"}, []string{"p"}},
		{"P02 W3", "open(my $f, '>p');", nil, []string{"p"}},
		{"P04 W2 +<", "open(my $f, '+<', 'p');", nil, []string{"p"}},
		{"P07 W1 unlink", "unlink('p');", nil, []string{"p"}},
		{"P08 W1 rename", "rename('a','p');", nil, []string{"a", "p"}},
		{"U20 W1 truncate", "truncate('p',0);", nil, []string{"p"}},
		{"U30 W1 link", "link('a','p');", nil, []string{"p"}},
		{"U33 W1 symlink", "symlink('a','p');", nil, []string{"p"}},
		{"X05 W3 concat", "open(my $f, '>' . 'p');", nil, []string{"p"}},
		{"X06 W2 concat", "open(my $f, '+<' . '', 'p');", nil, []string{"p"}},
		{"X07 W1 concat", "unlink('' . 'p');", nil, []string{"p"}},
		{"E01 W4 scalar", "my $m = '>'; open(my $f, $m, 'p');", nil, []string{"p"}},
		{"B10 data read", "__END__\nunlink('p');", nil, nil},
		{"B14 user sub", "sub unlink {1}; &unlink('p');", nil, nil},
		{"F01 comment", "# unlink('p')", nil, nil},
		{"F02 string", "print \"unlink('p')\";", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			got := literalInterpreterWrites(tc.code, "perl", "/tmp", "/tmp")
			for _, path := range tc.spec {
				if !slices.Contains(got, path) {
					t.Errorf("missing %q: got %v (rel %v, spec %v)", path, got, tc.rel, tc.spec)
				}
			}
			for _, path := range got {
				if !slices.Contains(tc.spec, path) {
					t.Errorf("extra %q: rel %v, spec %v", path, tc.rel, tc.spec)
				}
			}
		})
	}
}

func TestPerlStageTwoUnprovenScalar(t *testing.T) {
	cases := []string{
		"my $m = '<'; if ($x) $m = '>'; open(my $f, $m, 'p');",
		"my $m = '>'; f($m); open(my $f, $m, 'p');",
		"my $m = '>'; chop($m); open(my $f, $m, 'p');",
		"my $m = '>' if $x; open(my $f, $m, 'p');",
	}
	for _, code := range cases {
		t.Run(code, func(t *testing.T) {
			got := literalInterpreterWrites(code, "perl", "/tmp", "/tmp")
			if slices.Contains(got, "p") {
				t.Fatalf("unproven scalar raised: %v", got)
			}
		})
	}
}

func TestPerlSpecStageTwoLexerRows(t *testing.T) {
	cases := []struct {
		id, code  string
		rel, spec bool
	}{
		{"N01 hashkey y", "my %p; $p{y}=1; unlink 'p';", false, true},
		{"N03 arrow key m", "my $h={}; $h->{m}=1; unlink 'p';", false, true},
		{"N04 filetest s", "print -s 'notes.txt'; unlink 'p';", false, true},
		{"N08 s replacement", "$_='a'; s{a}\n{unlink 'p'}e;", false, true},
		{"N09 heredoc", "print <<X;\n__END__\nX\nunlink 'p';", false, true},
		{"N11 POD", "=pod\n__END__\n=cut\nunlink 'p';", false, true},
		{"N14 hash term star", "my %h=(a=>1); print $h{a}*unlink 'p';", false, true},
		{"N15 hash term amp", "my %h=(a=>1); print $h{a}&unlink('p');", false, true},
		{"N23 data in string", "print \"x\n__END__\n\"; unlink 'p';", false, true},
		{"N28 s comment replacement", "$_='a'; s{a} # comment\n {unlink 'p'}e;", false, true},
		{"B10 data inert", "__END__\nunlink 'p';", false, false},
		{"B14 amp user", "&unlink('p');", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			got := literalInterpreterWrites(tc.code, "perl", "/tmp", "/tmp")
			if slices.Contains(got, "p") != tc.spec {
				t.Fatalf("got %v, rel %v, spec %v", got, tc.rel, tc.spec)
			}
		})
	}
}

func TestPerlSpecStageTwoFocusedRows(t *testing.T) {
	data, err := os.ReadFile("testdata/perl_spec_stage2.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Case string
		Cmd  string
		Rel  string
		Spec string
		Rule string
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 46 {
		t.Fatalf("got %d focused rows, want 46", len(rows))
	}
	for _, row := range rows {
		t.Run(row.Case, func(t *testing.T) {
			if row.Rel != "AA" || row.Spec != "LB" {
				t.Fatalf("bad table verdict: rel=%s spec=%s", row.Rel, row.Spec)
			}
			paths := LiteralWriteOperands(row.Cmd, os.TempDir(), os.TempDir())
			found := false
			for _, path := range paths {
				if strings.Contains(path, ".claude") {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("%s: rel=%s spec=%s rule=%s paths=%v", row.Case, row.Rel, row.Spec, row.Rule, paths)
			}
		})
	}
}

func TestPerlSpecStageTwoBenignControls(t *testing.T) {
	data, err := os.ReadFile("testdata/perl_spec_stage2_controls.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Case string
		Cmd  string
		Rel  string
		Spec string
		Rule string
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 16 {
		t.Fatalf("got %d controls, want 16", len(rows))
	}
	for _, row := range rows {
		t.Run(row.Case, func(t *testing.T) {
			if row.Rel != "AA" || row.Spec != "AA" {
				t.Fatalf("bad table verdict: rel=%s spec=%s", row.Rel, row.Spec)
			}
			paths := LiteralWriteOperands(row.Cmd, os.TempDir(), os.TempDir())
			for _, path := range paths {
				if strings.Contains(path, ".claude") {
					t.Fatalf("%s: benign control raised: %v rule=%s", row.Case, paths, row.Rule)
				}
			}
		})
	}
}

func TestPerlStageTwoDupIsHandle(t *testing.T) {
	for _, code := range []string{
		"open(my $f, '>&p');",
		"open(my $f, '>&', 'p');",
		"open(my $f, '<&p');",
	} {
		t.Run(code, func(t *testing.T) {
			got := literalInterpreterWrites(code, "perl", "/tmp", "/tmp")
			if slices.Contains(got, "p") {
				t.Fatalf("dup raised path: %v", got)
			}
		})
	}
}

func TestPerlSpecStageTwoCorpusRows(t *testing.T) {
	data, err := os.ReadFile("testdata/perl_spec_stage2_corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		ID   string
		Rule string
		Cmd  string
		Rel  string
		Spec string
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 80 {
		t.Fatalf("got %d corpus rows, want 80", len(rows))
	}
	for _, row := range rows {
		t.Run(row.ID, func(t *testing.T) {
			if row.Rel != "AA" || row.Spec != "LB" {
				t.Fatalf("bad table verdict: rel=%s spec=%s", row.Rel, row.Spec)
			}
			paths := LiteralWriteOperands(row.Cmd, os.TempDir(), os.TempDir())
			found := false
			for _, path := range paths {
				if strings.Contains(path, ".claude") {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("corpus row %s: rel=AA spec=LB rule=%s", row.ID, row.Rule)
			}
		})
	}
}
