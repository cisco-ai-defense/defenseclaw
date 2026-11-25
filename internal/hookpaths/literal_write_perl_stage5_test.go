// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestPerlStageFivePipeForms(t *testing.T) {
	cases := []struct {
		name, code string
		write      bool
	}{
		{"S06 list pipe", `open(my $p, "|-", "tee", ".claude/settings.json");`, true},
		{"S07 two argument pipe", `open(P, "| tee .claude/settings.json");`, true},
		{"X23 trailing pipe", `open(P, "echo x > .claude/settings.json|");`, true},
		{"pipe read", `open(P, "| cat .claude/settings.json");`, false},
		{"list argument metacharacter", `open(P, "|-", "echo", "x > .claude/settings.json");`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			paths := literalInterpreterWrites(tc.code, "perl", "/tmp", "/tmp")
			found := slices.ContainsFunc(paths, func(p string) bool { return strings.Contains(p, ".claude/settings.json") })
			if found != tc.write {
				t.Fatalf("paths = %v, want write %v", paths, tc.write)
			}
		})
	}
}

func TestPerlSpecSectionTwoFocusedTable(t *testing.T) {
	data, err := os.ReadFile("testdata/perl_spec_section22.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Case, Cmd, Rel, Spec, Rule, Vs string
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 197 {
		t.Fatalf("got %d §2.2 rows, want 197", len(rows))
	}
	raises := 0
	for _, row := range rows {
		t.Run(row.Case, func(t *testing.T) {
			paths := LiteralWriteOperands(row.Cmd, "/tmp", "/tmp")
			if row.Case == "gap0592_perl:P09 in-place edit" {
				// The rel -i reader is in the gateway, verified by
				// TestPerlSpecFocusedP09RelInPlace.
				if row.Rel != "LB" || row.Spec != "LB" {
					t.Fatal("bad pinned -i verdict")
				}
				return
			}
			protected := slices.ContainsFunc(paths, func(p string) bool {
				return strings.Contains(p, ".claude/") || strings.Contains(p, ".ssh/")
			})
			want := row.Spec == "LB"
			if protected != want {
				t.Errorf("got protected=%v paths=%v; rel=%s spec=%s rule=%s", protected, paths, row.Rel, row.Spec, row.Rule)
			}
		})
		if row.Spec == "LB" && row.Rel == "AA" {
			raises++
		}
	}
	if raises != 97 {
		t.Fatalf("got %d focused raises, want 97", raises)
	}
}

func TestPerlStageFiveOpaqueBindingBarrier(t *testing.T) {
	cases := []struct {
		name, code string
		write      bool
	}{
		{"string eval barrier", `my $m='>'; eval "1"; open(F,$m,'p');`, false},
		{"q eval barrier", `my $m='>'; eval q{1}; open(F,$m,'p');`, false},
		{"variable eval barrier", `my $m='>'; eval $x; open(F,$m,'p');`, false},
		{"do expression barrier", `my $m='>'; do $x; open(F,$m,'p');`, false},
		{"require expression barrier", `my $m='>'; require "x.pl"; open(F,$m,'p');`, false},
		{"symbolic dereference barrier", `my $m='>'; ${"x"}; open(F,$m,'p');`, false},
		{"block eval ordinary", `my $m='>'; eval { 1 }; open(F,$m,'p');`, true},
		{"require module ordinary", `my $m='>'; require File::Copy; open(F,$m,'p');`, true},
		{"opaque leaves literal proof", `eval "x"; unlink('p');`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			paths := literalInterpreterWrites(tc.code, "perl", "/tmp", "/tmp")
			if slices.Contains(paths, "p") != tc.write {
				t.Fatalf("paths = %v, want write %v", paths, tc.write)
			}
		})
	}
}

func TestPerlSpecSectionTwoThreeVariants(t *testing.T) {
	prefix := `use Fcntl; sub helper { 1 }; BEGIN { 1 }; helper(); `
	target := `sysopen(my $f,".claude/settings.json",O_RDONLY) or die $!; print <$f>`
	cases := []string{prefix + target}
	for i := 1; i <= len(prefix); i++ {
		cases = append(cases, prefix[:i]+"; "+target)
	}
	if len(cases) != 53 {
		t.Fatalf("RVh variants=%d, want 53", len(cases))
	}
	for i, code := range cases {
		t.Run("RVh_"+strconv.Itoa(i), func(t *testing.T) {
			paths := literalInterpreterWrites(code, "perl", "/tmp", "/tmp")
			if slices.ContainsFunc(paths, func(p string) bool { return strings.Contains(p, ".claude/settings.json") }) {
				t.Fatalf("read variant raised: %v", paths)
			}
		})
	}
	other := []struct {
		name, code string
		write      bool
	}{
		{"RVi1 unrelated constant read", `use Fcntl; use constant { O_NOFOLLOW => 1 }; sub helper {1}; helper(); sysopen(my $f,".claude/settings.json",O_RDONLY);`, false},
		{"RVi2 matching constant write", `use Fcntl; use constant { O_RDONLY => 1 }; sub helper {1}; helper(); sysopen(my $f,".claude/settings.json",O_RDONLY);`, true},
		{"RVi3 unrelated constant literal read", `use Fcntl; use constant { O_NOFOLLOW => 1 }; sub helper {1}; helper(); open(my $f,"<",".claude/settings.json");`, false},
		{"RVeX04 S1 read", `my $m="<"; open(my $f,$m,".claude/settings.json");`, false},
		{"RVeX05 other file write", `my $m=">"; open(my $f,$m,"notes.txt");`, false},
	}
	for _, tc := range other {
		t.Run(tc.name, func(t *testing.T) {
			paths := literalInterpreterWrites(tc.code, "perl", "/tmp", "/tmp")
			got := slices.ContainsFunc(paths, func(p string) bool { return strings.Contains(p, ".claude/settings.json") })
			if got != tc.write {
				t.Fatalf("paths=%v, want write %v", paths, tc.write)
			}
		})
	}
}
