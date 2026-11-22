// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// bashGlobMatchNames is the folder of the differential test: plain names,
// a leading bracket, a dash, mixed case and a digit.
var bashGlobMatchNames = []string{"nmq", "nmx", "nmz", "nm!", "nm^", "nm-", "nm]", "nm[", "nmQ", "nm7", "nm_", "nm.", "nmab", "Nmq"}

// bashGlobMatchPatterns are pattern forms Go's filepath.Match and bash read
// differently, and the ones they agree on (rel-1-0-10:GAP-0378).
var bashGlobMatchPatterns = []string{
	"nm[!z]", "nm[^z]", "nm[!a-p]", "nm[[:alpha:]]", "nm[[:digit:]]", "nm[[:alnum:]]", "nm[[:punct:]]",
	"nm[[:upper:]]", "nm[[:lower:]]", "nm[[:word:]]", "nm[]q]", "nm[q-]", "nm[-q]", "nm[!]]", "nm[\\]]",
	"nm[!q-z]", "nm[0-9]", "nm[q]", "nm?", "nm*", "nm[", "*q", "nm[[:alpha:]-]", "nm[[=q=]]", "nm[[.q.]]",
	"nm[!-]", "n?[qx]", "nm[!!]", "nm[a-z]",
}

// bashGlobMatchWant is real bash 5 in the C locale over bashGlobMatchNames
// (shopt -s nullglob; printf '%s\n' PATTERN). TestBashGlobMatchAgreesWithRealBash
// re-derives it on every host with bash 5.
var bashGlobMatchWant = map[string][]string{
	"nm[!z]":         {"nm!", "nm-", "nm.", "nm7", "nmQ", "nm[", "nm]", "nm^", "nm_", "nmq", "nmx"},
	"nm[^z]":         {"nm!", "nm-", "nm.", "nm7", "nmQ", "nm[", "nm]", "nm^", "nm_", "nmq", "nmx"},
	"nm[!a-p]":       {"nm!", "nm-", "nm.", "nm7", "nmQ", "nm[", "nm]", "nm^", "nm_", "nmq", "nmx", "nmz"},
	"nm[[:alpha:]]":  {"nmQ", "nmq", "nmx", "nmz"},
	"nm[[:digit:]]":  {"nm7"},
	"nm[[:alnum:]]":  {"nm7", "nmQ", "nmq", "nmx", "nmz"},
	"nm[[:punct:]]":  {"nm!", "nm-", "nm.", "nm[", "nm]", "nm^", "nm_"},
	"nm[[:upper:]]":  {"nmQ"},
	"nm[[:lower:]]":  {"nmq", "nmx", "nmz"},
	"nm[[:word:]]":   {"nm7", "nmQ", "nm_", "nmq", "nmx", "nmz"},
	"nm[]q]":         {"nm]", "nmq"},
	"nm[q-]":         {"nm-", "nmq"},
	"nm[-q]":         {"nm-", "nmq"},
	"nm[!]]":         {"nm!", "nm-", "nm.", "nm7", "nmQ", "nm[", "nm^", "nm_", "nmq", "nmx", "nmz"},
	"nm[\\]]":        {"nm]"},
	"nm[!q-z]":       {"nm!", "nm-", "nm.", "nm7", "nmQ", "nm[", "nm]", "nm^", "nm_"},
	"nm[0-9]":        {"nm7"},
	"nm[q]":          {"nmq"},
	"nm?":            {"nm!", "nm-", "nm.", "nm7", "nmQ", "nm[", "nm]", "nm^", "nm_", "nmq", "nmx", "nmz"},
	"nm*":            {"nm!", "nm-", "nm.", "nm7", "nmQ", "nm[", "nm]", "nm^", "nm_", "nmab", "nmq", "nmx", "nmz"},
	"nm[":            {"nm["},
	"*q":             {"Nmq", "nmq"},
	"nm[[:alpha:]-]": {"nm-", "nmQ", "nmq", "nmx", "nmz"},
	"nm[[=q=]]":      {"nmq"},
	"nm[[.q.]]":      {"nmq"},
	"nm[!-]":         {"nm!", "nm.", "nm7", "nmQ", "nm[", "nm]", "nm^", "nm_", "nmq", "nmx", "nmz"},
	"n?[qx]":         {"nmq", "nmx"},
	"nm[!!]":         {"nm-", "nm.", "nm7", "nmQ", "nm[", "nm]", "nm^", "nm_", "nmq", "nmx", "nmz"},
	"nm[a-z]":        {"nmq", "nmx", "nmz"},
}

func bashGlobMatchSet(pattern string, names []string, fold bool) (got []string, exact bool) {
	exact = true
	for _, name := range names {
		matched, ok := bashGlobMatch(pattern, name, fold)
		exact = exact && ok
		if matched {
			got = append(got, name)
		}
	}
	slices.Sort(got)
	return got, exact
}

func TestBashGlobMatchReadsBracketFormsAsBash(t *testing.T) {
	for _, pattern := range bashGlobMatchPatterns {
		want, ok := bashGlobMatchWant[pattern]
		if !ok {
			t.Fatalf("%q: no expected set", pattern)
		}
		got, _ := bashGlobMatchSet(pattern, bashGlobMatchNames, false)
		if !slices.Equal(got, want) {
			t.Errorf("%q: got %q, want %q (bash 5, C locale)", pattern, got, want)
		}
	}
}

func TestBashGlobMatchExactness(t *testing.T) {
	for _, tc := range []struct {
		pattern, name string
		fold, exact   bool
	}{
		{"nm[!z]", "nmq", false, true},
		{"nm[[:alpha:]]", "nmq", false, true},
		{"nm[a-z]", "nmq", false, true},
		{"nm[a-z]", "nmQ", false, false},       // bash 4 in a UTF-8 locale interleaves the cases
		{"nm[[:alpha:]]", "nmé", false, false}, // the locale decides
		{"nm?", "nmé", false, false},           // one character or two bytes
		{"nm?", "nmq", false, true},
		{"nm[[:upper:]]", "nmq", true, false}, // nocaseglob and a case class
		{"NM?", "nmq", true, true},
		{"nm[+-~]", "nmq", false, false}, // a punctuation range follows the collation
		{"nm[[.space.]]", "nm ", false, false},
	} {
		if _, exact := bashGlobMatch(tc.pattern, tc.name, tc.fold); exact != tc.exact {
			t.Errorf("%q %q fold=%v: exact %v, want %v", tc.pattern, tc.name, tc.fold, exact, tc.exact)
		}
	}
}

// TestBashGlobMatchAgreesWithRealBash runs every pattern through the host's
// bash 5 in the C locale over the same names, with and without nocaseglob.
func TestBashGlobMatchAgreesWithRealBash(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows walk reads PowerShell and cmd wildcards")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash on this host")
	}
	version, err := exec.Command(bash, "-c", "echo ${BASH_VERSINFO[0]}").Output()
	if err != nil || strings.TrimSpace(string(version)) < "5" {
		t.Skipf("bash %s: globasciiranges is on by default only from bash 5", strings.TrimSpace(string(version)))
	}
	dir := t.TempDir()
	for _, name := range bashGlobMatchNames {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Skipf("file system refuses %q: %v", name, err)
		}
	}
	for _, fold := range []bool{false, true} {
		for _, pattern := range bashGlobMatchPatterns {
			script := "shopt -s nullglob\n"
			if fold {
				script += "shopt -s nocaseglob\n"
			}
			script += "for f in " + pattern + "; do printf '%s\\n' \"$f\"; done\n"
			cmd := exec.Command(bash, "--norc", "--noprofile", "-c", script)
			cmd.Dir = dir
			cmd.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin"}
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("%q fold=%v: bash: %v", pattern, fold, err)
			}
			var want []string
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				if line != "" {
					want = append(want, line)
				}
			}
			slices.Sort(want)
			got, exact := bashGlobMatchSet(pattern, bashGlobMatchNames, fold)
			if exact && !slices.Equal(got, want) {
				t.Errorf("%q fold=%v: got %q, bash %q", pattern, fold, got, want)
			}
		}
	}
}
