// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"testing"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

func TestLateHasPathBackslash(t *testing.T) {
	for _, row := range []struct {
		literal string
		want    bool
	}{
		{`C:\Users\me\file`, true},
		{`dir\sub.txt`, true},
		{`dir\_x`, true},
		{`dir\9`, true},
		{`C:\\Users\\me`, false},
		{`one\ two`, false},
		{`quote\"`, false},
		{`dollar\$HOME`, false},
		{`glob\*`, false},
		{`trailing\`, false},
		{`plain/path/file`, false},
		{``, false},
	} {
		if got := lateHasPathBackslash(row.literal); got != row.want {
			t.Errorf("lateHasPathBackslash(%q)=%v, want %v", row.literal, got, row.want)
		}
	}
}

func lateExpandedWord(t *testing.T, text string, spelled bool) string {
	t.Helper()
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader("cat "+text), "")
	if err != nil {
		t.Fatal(err)
	}
	word := file.Stmts[0].Cmd.(*syntax.CallExpr).Args[1]
	if spelled {
		word = lateWindowsPathWord(word)
	}
	fields, err := expand.Fields(&expand.Config{Env: expand.ListEnviron("HOME=/home/me")}, word)
	if err != nil || len(fields) != 1 {
		t.Fatalf("expand %q: %v %v", text, fields, err)
	}
	return fields[0]
}

// A drive path with backslash separators keeps them; the same word read as
// POSIX loses them. A word without such a backslash reads as it did.
func TestLateWindowsPathWordKeepsTheBackslashesOfADrivePath(t *testing.T) {
	for _, row := range []struct{ text, posix, windows string }{
		{`C:\Users\me\file`, `C:Usersmefile`, `C:\Users\me\file`},
		{`C:\Users\me/../status`, `C:Usersme/../status`, `C:\Users\me/../status`},
		{`C:\\Users\\me`, `C:\Users\me`, `C:\Users\me`},
		{`one\ two`, `one two`, `one two`},
		{`'C:\Users'`, `C:\Users`, `C:\Users`},
		{`"C:\Users"`, `C:\Users`, `C:\Users`},
		{`plain/file`, `plain/file`, `plain/file`},
	} {
		if got := lateExpandedWord(t, row.text, false); got != row.posix {
			t.Errorf("POSIX reading of %s = %q, want %q", row.text, got, row.posix)
		}
		if got := lateExpandedWord(t, row.text, true); got != row.windows {
			t.Errorf("Windows reading of %s = %q, want %q", row.text, got, row.windows)
		}
	}
}

func TestLateWindowsAliasIsAProcessRelativeSpelling(t *testing.T) {
	for _, row := range []struct {
		word string
		want bool
	}{
		{"/proc/self/cwd/alias", true},
		{"/proc/thread-self/cwd/alias", true},
		{"/proc/self/root" + `C:\Users\me\alias`, true},
		{"/proc/self", true},
		{"/dev/fd/3", true},
		{"/dev/stdin", true},
		{`\dev\fd\3`, true},
		{"/proc/selfish/x", false},
		{"/proc/1234/cwd", false},
		{"/dev/null", false},
		{"/tmp/proc/self", false},
		{"notes", false},
	} {
		if got := lateWindowsAlias(row.word); got != row.want {
			t.Errorf("lateWindowsAlias(%q)=%v, want %v", row.word, got, row.want)
		}
	}
}

func TestLateWindowsDrivePathMapsAGitBashDriveMount(t *testing.T) {
	for word, want := range map[string]string{
		"/c/Users/me/f":       "C:/Users/me/f",
		"/cygdrive/d/work":    "D:/work",
		"/c":                  "C:/",
		"/tmp/f":              "/tmp/f",
		"/cc/f":               "/cc/f",
		`C:\Users\me`:         `C:\Users\me`,
		"relative/c/Users/me": "relative/c/Users/me",
	} {
		if got := lateWindowsDrivePath(word); got != want {
			t.Errorf("lateWindowsDrivePath(%q)=%q, want %q", word, got, want)
		}
	}
}
