// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestPerlStageFourUseConstant(t *testing.T) {
	cases := []struct {
		id, code string
		write    bool
	}{
		{"N1 simple", "use constant O_NOFOLLOW => 1; sysopen(F,'p',O_NOFOLLOW);", true},
		{"N1 hash", "use constant { O_NOFOLLOW => 1, OTHER => 0 }; sysopen(F,'p',O_NOFOLLOW);", true},
		{"N1 shadow import", "use Fcntl; use constant O_RDONLY => 1; sysopen(F,'p',O_RDONLY);", true},
		{"N1 unrelated hash", "use Fcntl; use constant { O_NOFOLLOW => 1 }; sysopen(F,'p',O_RDONLY);", false},
		{"N1 unknown", "use Fcntl; use constant O_WRONLY => mystery(); sysopen(F,'p',O_WRONLY);", false},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			got := literalInterpreterWrites(tc.code, "perl", "/tmp", "/tmp")
			if slices.Contains(got, "p") != tc.write {
				t.Fatalf("paths = %v, want write %v", got, tc.write)
			}
		})
	}
}

func TestPerlStageFourLauncherConstant(t *testing.T) {
	cases := []struct {
		cmd   string
		write bool
	}{
		{"perl -Mconstant=O_RDONLY,1 -e 'sysopen(F,\"p\",O_RDONLY);'", true},
		{"perl -Mconstant=O_RDONLY,read -e 'sysopen(F,\"p\",O_RDONLY);'", false},
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			paths := LiteralWriteOperands(tc.cmd, os.TempDir(), os.TempDir())
			if slices.Contains(paths, filepath.Join(os.TempDir(), "p")) != tc.write {
				t.Fatalf("paths = %v, want write %v", paths, tc.write)
			}
		})
	}
}

func TestPerlStageFourConstantSub(t *testing.T) {
	cases := []struct {
		id, code string
		write    bool
	}{
		{"N2 prototype", "sub O_NOFOLLOW () { 1 }; sysopen(F,'p',O_NOFOLLOW);", true},
		{"N2 no prototype", "sub O_NOFOLLOW { 1 }; sysopen(F,'p',O_NOFOLLOW);", true},
		{"N2 return", "sub O_NOFOLLOW { return 1 }; sysopen(F,'p',O_NOFOLLOW);", true},
		{"N2 main qualified", "sub main::O_NOFOLLOW { 1 }; sysopen(F,'p',O_NOFOLLOW);", true},
		{"N2 root qualified", "sub ::O_NOFOLLOW { 1 }; sysopen(F,'p',O_NOFOLLOW);", true},
		{"N2 other package", "sub Fcntl::O_NOFOLLOW { 1 }; sysopen(F,'p',O_NOFOLLOW);", false},
		{"N2 read shadow", "use Fcntl; sub O_WRONLY { 0 }; sysopen(F,'p',O_WRONLY);", false},
		{"N2 unknown body", "use Fcntl; sub O_WRONLY { mystery() }; sysopen(F,'p',O_WRONLY);", false},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			got := literalInterpreterWrites(tc.code, "perl", "/tmp", "/tmp")
			if slices.Contains(got, "p") != tc.write {
				tokens, complete := perlLex(tc.code)
				defs := perlNamedDefinitions(nil, tokens)
				t.Fatalf("paths = %v, want write %v, complete=%v tokens=%v defs=%v", got, tc.write, complete, tokens, defs)
			}
		})
	}
}

func TestPerlStageFourGlobDefinition(t *testing.T) {
	cases := []struct {
		id, code string
		write    bool
	}{
		{"N3 runtime bare", "*O_NOFOLLOW = sub { 1 }; sysopen(F,'p',O_NOFOLLOW);", false},
		{"N3 runtime call", "*O_NOFOLLOW = sub { 1 }; sysopen(F,'p',O_NOFOLLOW());", true},
		{"N3 runtime amp", "*O_NOFOLLOW = sub { 1 }; sysopen(F,'p',&O_NOFOLLOW);", true},
		{"N3 BEGIN bare", "BEGIN { *O_NOFOLLOW = sub { 1 } }; sysopen(F,'p',O_NOFOLLOW);", true},
		{"N3 eval block call", "eval { *O_NOFOLLOW = sub { 1 } }; sysopen(F,'p',O_NOFOLLOW());", true},
		{"N3 package spelling", "*Fcntl::O_NOFOLLOW = sub { 1 }; sysopen(F,'p',O_NOFOLLOW());", false},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			got := literalInterpreterWrites(tc.code, "perl", "/tmp", "/tmp")
			if slices.Contains(got, "p") != tc.write {
				t.Fatalf("paths = %v, want write %v", got, tc.write)
			}
		})
	}
}

func TestPerlSpecStageFourDefinitionRows(t *testing.T) {
	data, err := os.ReadFile("testdata/perl_spec_stage4_defs.json")
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
	if len(rows) != 26 {
		t.Fatalf("got %d rows, want 26", len(rows))
	}
	for _, row := range rows {
		t.Run(row.Case, func(t *testing.T) {
			if row.Rel != "AA" || row.Spec != "LB" {
				t.Fatalf("bad table verdict rel=%s spec=%s", row.Rel, row.Spec)
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
				t.Fatalf("%s: rel=%s spec=%s rule=%s", row.Case, row.Rel, row.Spec, row.Rule)
			}
		})
	}
}

func TestPerlStageFourDefinitionOrder(t *testing.T) {
	cases := []struct {
		id, code string
		write    bool
	}{
		{"top level later read", "use constant O_NOFOLLOW => 1; use constant O_NOFOLLOW => 0; sysopen(F,'p',O_NOFOLLOW);", false},
		{"top level later write", "use constant O_NOFOLLOW => 0; use constant O_NOFOLLOW => 1; sysopen(F,'p',O_NOFOLLOW);", true},
		{"nested conflict unknown", "sub helper { use constant O_NOFOLLOW => 1 }; use constant O_NOFOLLOW => 0; sysopen(F,'p',O_NOFOLLOW);", false},
		{"unknown shadow", "use Fcntl; use constant O_WRONLY => mystery(); sysopen(F,'p',O_WRONLY);", false},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			got := literalInterpreterWrites(tc.code, "perl", "/tmp", "/tmp")
			if slices.Contains(got, "p") != tc.write {
				t.Fatalf("paths = %v, want write %v", got, tc.write)
			}
		})
	}
}

func TestPerlStageFourS2UncalledHelperFlagsRel(t *testing.T) {
	code := "sub helper { $flags = 1 }; sysopen(my $fh, 'p', $flags);"
	got := literalInterpreterWrites(code, "perl", "/tmp", "/tmp")
	if slices.Contains(got, "p") {
		t.Fatalf("S2-only write must keep rel verdict, got %v", got)
	}
}

func TestPerlStageFourS2UncalledHelperModeRel(t *testing.T) {
	code := "sub helper { $mode = '>' }; open(my $fh, $mode, 'p');"
	got := literalInterpreterWrites(code, "perl", "/tmp", "/tmp")
	if slices.Contains(got, "p") {
		t.Fatalf("S2-only write must keep rel verdict, got %v", got)
	}
}

func TestPerlSpecStageFourScalarRows(t *testing.T) {
	data, err := os.ReadFile("testdata/perl_spec_stage4_scalars.json")
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
	if len(rows) != 15 {
		t.Fatalf("got %d rows, want 15", len(rows))
	}
	for _, row := range rows {
		t.Run(row.Case, func(t *testing.T) {
			if row.Rel != "AA" || row.Spec != "LB" {
				t.Fatalf("bad table verdict rel=%s spec=%s", row.Rel, row.Spec)
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
				t.Fatalf("%s: rel=%s spec=%s rule=%s", row.Case, row.Rel, row.Spec, row.Rule)
			}
		})
	}
}

func TestPerlSpecStageFourOverrideRows(t *testing.T) {
	data, err := os.ReadFile("testdata/perl_spec_stage4_overrides.json")
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
	if len(rows) != 12 {
		t.Fatalf("got %d rows, want 12", len(rows))
	}
	for _, row := range rows {
		t.Run(row.Case, func(t *testing.T) {
			if row.Rel != "AA" || row.Spec != "LB" {
				t.Fatalf("bad table verdict rel=%s spec=%s", row.Rel, row.Spec)
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
				t.Fatalf("%s: rel=%s spec=%s rule=%s", row.Case, row.Rel, row.Spec, row.Rule)
			}
		})
	}
}

func TestPerlStageFourBenignOverrides(t *testing.T) {
	cases := []struct {
		code  string
		write bool
	}{
		{"sub open (*;$@) { 1 }; open(F,'<','p');", false},
		{"use subs 'unlink'; sub unlink { 1 }; unlink('p');", false},
		{"BEGIN { *CORE::GLOBAL::unlink = sub { 1 } }; unlink('p');", false},
		{"print \"use subs unlink\"; unlink('p');", true},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			got := literalInterpreterWrites(tc.code, "perl", "/tmp", "/tmp")
			if slices.Contains(got, "p") != tc.write {
				t.Fatalf("paths = %v, want write %v", got, tc.write)
			}
		})
	}
}

func TestPerlStageFourS1Enclosing(t *testing.T) {
	cases := []struct {
		name, code string
		write      bool
	}{
		{"plain nested block", "my $m='>'; { open(my $f,$m,'p') }", true},
		{"sub boundary", "my $m='>'; sub later { open(my $f,$m,'p') }", false},
		{"loop boundary", "my $m='>'; for (1) { open(my $f,$m,'p') }", false},
		{"exited sibling", "{ my $m='>' } { open(my $f,$m,'p') }", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := literalInterpreterWrites(tc.code, "perl", "/tmp", "/tmp")
			if slices.Contains(got, "p") != tc.write {
				t.Fatalf("paths = %v, want write %v", got, tc.write)
			}
		})
	}
}
