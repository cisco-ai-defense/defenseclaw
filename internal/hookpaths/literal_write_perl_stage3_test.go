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

func TestPerlFlagVisibilitySeventeenForms(t *testing.T) {
	cases := []struct {
		id, code, moduleSwitch string
		write                  bool
	}{
		{"bare no import", "sysopen(F,'p',O_WRONLY);", "", false},
		{"use Fcntl", "use Fcntl; sysopen(F,'p',O_WRONLY);", "", true},
		{"Fcntl flock only", "use Fcntl qw(:flock); sysopen(F,'p',O_WRONLY);", "", false},
		{"Fcntl named import", "use Fcntl qw(O_WRONLY); sysopen(F,'p',O_WRONLY);", "", true},
		{"Fcntl quoted import", "use Fcntl ('O_WRONLY'); sysopen(F,'p',O_WRONLY);", "", true},
		{"Fcntl empty import", "use Fcntl (); sysopen(F,'p',O_WRONLY);", "", false},
		{"use POSIX", "use POSIX; sysopen(F,'p',O_WRONLY);", "", true},
		{"POSIX empty import", "use POSIX (); sysopen(F,'p',O_WRONLY);", "", false},
		{"use IO File", "use IO::File; sysopen(F,'p',O_WRONLY);", "", true},
		{"MFcntl", "sysopen(F,\"p\",O_WRONLY);", "-MFcntl", true},
		{"MPOSIX", "sysopen(F,\"p\",O_WRONLY);", "-MPOSIX", true},
		{"qualified no load", "sysopen(F,'p',Fcntl::O_WRONLY);", "", false},
		{"qualified use empty", "use Fcntl (); sysopen(F,'p',Fcntl::O_WRONLY);", "", true},
		{"qualified call require", "require Fcntl; sysopen(F,'p',Fcntl::O_WRONLY());", "", true},
		{"amp qualified require", "require Fcntl; sysopen(F,'p',&Fcntl::O_WRONLY);", "", true},
		{"BEGIN require qualified", "BEGIN { require Fcntl }; sysopen(F,'p',Fcntl::O_WRONLY);", "", true},
		{"unimported call", "sysopen(F,'p',O_WRONLY());", "", false},
		{"strict unimported", "use strict; sysopen(F,'p',O_WRONLY);", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			var paths []string
			if tc.moduleSwitch == "" {
				paths = literalInterpreterWrites(tc.code, "perl", "/tmp", "/tmp")
			} else {
				cmd := "perl " + tc.moduleSwitch + " -e '" + tc.code + "'"
				paths = LiteralWriteOperands(cmd, os.TempDir(), os.TempDir())
			}
			wantPath := "p"
			if tc.moduleSwitch != "" {
				wantPath = filepath.Join(os.TempDir(), "p")
			}
			if slices.Contains(paths, wantPath) != tc.write {
				t.Fatalf("paths = %v, want write %v", paths, tc.write)
			}
		})
	}
}

func TestPerlFlagExpressionNumbers(t *testing.T) {
	cases := []struct {
		id, code string
		write    bool
	}{
		{"decimal", "sysopen(F,'p',1);", true},
		{"octal", "sysopen(F,'p',01|01000);", true},
		{"hex", "sysopen(F,'p',0x1);", true},
		{"binary", "sysopen(F,'p',0b1);", true},
		{"read zero", "sysopen(F,'p',0);", false},
		{"read imported", "use Fcntl; sysopen(F,'p',O_RDONLY);", false},
		{"unknown", "use Fcntl; sysopen(F,'p',O_MYSTERY);", false},
		{"expression", "use Fcntl; sysopen(F,'p',(O_RDONLY | O_CREAT));", true},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			paths := literalInterpreterWrites(tc.code, "perl", "/tmp", "/tmp")
			if slices.Contains(paths, "p") != tc.write {
				t.Fatalf("paths = %v, want write %v", paths, tc.write)
			}
		})
	}
}

func TestPerlSpecStageThreeFocusedRows(t *testing.T) {
	data, err := os.ReadFile("testdata/perl_spec_stage3.json")
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
	if len(rows) != 4 {
		t.Fatalf("got %d rows, want 4", len(rows))
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

func TestPerlSpecStageThreeCorpusRows(t *testing.T) {
	data, err := os.ReadFile("testdata/perl_spec_stage3_corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		ID   string
		Cmd  string
		Rule string
		Rel  string
		Spec string
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 9 {
		t.Fatalf("got %d rows, want 9", len(rows))
	}
	for _, row := range rows {
		t.Run(row.ID, func(t *testing.T) {
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
				t.Fatalf("%s: rel=%s spec=%s rule=%s", row.ID, row.Rel, row.Spec, row.Rule)
			}
		})
	}
}

func TestPerlFlagRuntimeRequireNeedsStraightLine(t *testing.T) {
	cases := []string{
		"require Fcntl if 0; sysopen(F,'p',Fcntl::O_WRONLY());",
		"sub helper { require Fcntl }; sysopen(F,'p',Fcntl::O_WRONLY());",
		"require Fcntl; sub helper {1}; sysopen(F,'p',Fcntl::O_WRONLY());",
	}
	for _, code := range cases {
		t.Run(code, func(t *testing.T) {
			paths := literalInterpreterWrites(code, "perl", "/tmp", "/tmp")
			if slices.Contains(paths, "p") {
				t.Fatalf("unproven require raised: %v", paths)
			}
		})
	}
}

func TestPerlFlagReadSetAndWholeExpression(t *testing.T) {
	cases := []struct {
		code  string
		write bool
	}{
		{"use Fcntl; sysopen(F,'p',O_RDONLY|O_NOFOLLOW);", false},
		{"use Fcntl; sysopen(F,'p',O_WRONLY|O_NOFOLLOW);", true},
		{"use Fcntl qw(O_WRONLY); sysopen(F,'p',O_WRONLY|O_CREAT);", false},
		{"use Fcntl qw(:DEFAULT); sysopen(F,'p',O_WRONLY|O_CREAT);", true},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			paths := literalInterpreterWrites(tc.code, "perl", "/tmp", "/tmp")
			if slices.Contains(paths, "p") != tc.write {
				t.Fatalf("paths = %v, want write %v", paths, tc.write)
			}
		})
	}
}
