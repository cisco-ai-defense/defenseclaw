// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// rel-1-0-10 GAP-0415: the managed carry of the client decision is removed for
// an awk call whose inline program has no file output (a protected name in a
// regular expression or an input operand is not a write), and only for that.
func TestGAP0415AwkProgramWithoutOutputIsNoWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged home")
	}
	home := filepath.Join(t.TempDir(), "eng1")
	project := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "writer.awk"), []byte("BEGIN {print \"x\" >> \"alias\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(project, "alias")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for _, tc := range []struct {
		name, command string
		noWrite       bool
	}{
		{"regular expression names the link, dynamic input", `awk '/print > "alias"/ {print}' "$input"`, true},
		{"program names the link as data, dynamic input", `awk '{print "alias"}' "$input"`, true},
		{"output to the link", `awk 'BEGIN {print "x" >> "alias"}' "$input"`, false},
		{"output to the link under a regular expression", `awk '/x/ {print "x" > "alias"}' "$input"`, false},
		{"program file", `awk -f writer.awk "$input"`, false},
		{"attached program file", `awk -fwriter.awk "$input"`, false},
		{"long program file", `awk --file=writer.awk "$input"`, false},
		{"program from a variable", `p='{print}'; awk "$p" input.txt`, false},
		{"an in-place option", `gawk -i inplace '{print}' "$input"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := writersAllProvenSafe(tc.command, project, home, nil); got != tc.noWrite {
				t.Fatalf("writersAllProvenSafe = %v, want %v", got, tc.noWrite)
			}
		})
	}
}
