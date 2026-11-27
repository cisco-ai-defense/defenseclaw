// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"slices"
	"testing"
)

// TestGAP1288SedScriptWriteFiles: the files a sed script opens for writing
// by name (rel-1-0-10:GAP-1288, GAP-1318): w and W to the end of the line,
// the w flag of s, never /dev/stdout or /dev/stderr, never an r or R file.
// A script with e, or one the reader cannot settle, is not read.
func TestGAP1288SedScriptWriteFiles(t *testing.T) {
	for _, c := range []struct {
		script string
		want   []string
		ok     bool
	}{
		{"w key[9]", []string{"key[9]"}, true},
		{"s/a/b/w keya", []string{"keya"}, true},
		{"s/a/b/gw out file", []string{"out file"}, true},
		{"1,3W a; b\np", []string{"a; b"}, true},
		{"/x/{\nw one\n}\nw two", []string{"one", "two"}, true},
		{"r keya", nil, true},
		{"s/a/b/w /dev/stdout", nil, true},
		{":top\nn\nb top", nil, true},
		{"s/a/b/", nil, true},
		{"s/a/b/e", nil, false},
		{"e touch x", nil, false},
		{"w", nil, false},
		{"s/a/b", nil, false},
	} {
		got, ok := sedScriptWriteFiles(c.script)
		if ok != c.ok || !slices.Equal(got, c.want) {
			t.Errorf("sedScriptWriteFiles(%q) = %q, %v; want %q, %v", c.script, got, ok, c.want, c.ok)
		}
	}
	// The replace-only reading is unchanged: a w file is a write.
	for _, script := range []string{"w x", "s/a/b/w x", "r x", ":a"} {
		if sedScriptReplaceOnly(script) {
			t.Errorf("sedScriptReplaceOnly(%q) = true", script)
		}
	}
	if !sedScriptReplaceOnly("s/a/b/g") {
		t.Error("sedScriptReplaceOnly(s/a/b/g) = false")
	}
	for _, c := range []struct {
		args []string
		want []string
	}{
		{[]string{"-n", "w x", "f"}, []string{"w x"}},
		{[]string{"-e", "p", "--expression=w y", "f"}, []string{"p", "w y"}},
		{[]string{"-f", "w.sed", "f"}, nil},
		{[]string{"--file=w.sed", "-e", "w z"}, []string{"w z"}},
	} {
		if got, ok := sedScriptTexts(c.args); !ok || !slices.Equal(got, c.want) {
			t.Errorf("sedScriptTexts(%q) = %q, %v; want %q", c.args, got, ok, c.want)
		}
	}
}
