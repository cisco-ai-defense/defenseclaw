// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"slices"
	"testing"
)

// The Windows readings of the late reader are plain functions of the text, so
// every host runs them: a Windows runner is not needed to pin what a Windows
// host reads. A numbered process link is a link no file system of a Windows
// host holds (Git Bash provides it), so the hook cannot prove it.
func TestLateWindowsNumberedLinkIsUnprovedAndAPlainEntryIsNot(t *testing.T) {
	for word, want := range map[string]bool{
		"/proc/1/task/1/cwd/alias": true,
		`\proc\1234\cwd\alias`:     true,
		"/proc/1234/fd/3":          true,
		"/proc/1234/exe":           true,
		"/proc/1234/status":        false,
		"/proc/cpuinfo":            false,
		"/proc/self/cwd/alias":     false,
		"/proc/1234/fd":            false,
		"/proc/self/status":        false,
		"/home/user/proc/1/cwd":    false,
	} {
		if got := lateWindowsNumberedLink(word); got != want {
			t.Errorf("lateWindowsNumberedLink(%q) = %t, want %t", word, got, want)
		}
	}
}

// A path list in an assignment splits at its colons, and a Windows drive colon
// is not a separator. A list with a separator colon has no whole-value path,
// because the host cannot open a name with a colon inside; a drive path stays
// one path, and the elements of a list stay candidates in both readings.
func TestLateColonListElementsKeepsDrivePathsAndDropsTheListAsAPath(t *testing.T) {
	for _, row := range []struct {
		value   string
		windows bool
		want    []string
		whole   bool
	}{
		{"a:b:~/notes", false, []string{"a", "b", "~/notes"}, true},
		{"a:b:~/notes", true, []string{"a", "b", "~/notes"}, false},
		{"a:~/.ssh/authorized_keys", true, []string{"a", "~/.ssh/authorized_keys"}, false},
		{`C:\Users\u\.ssh\authorized_keys`, true, []string{`C:\Users\u\.ssh\authorized_keys`}, true},
		{`C:\x:D:/y`, true, []string{`C:\x`, "D:/y", "C", `\x`, "D", "/y"}, false},
		{"C:/Users/u/notes", true, []string{"C:/Users/u/notes"}, true},
		{"~/.ssh/authorized_keys:stream", true, []string{"~/.ssh/authorized_keys", "stream"}, false},
		{"a:/home/u", true, []string{"a:/home/u", "a", "/home/u"}, true},
		{`C:\Users\u`, false, []string{"C", `\Users\u`}, true},
	} {
		got, whole := lateColonListElements(row.value, row.windows)
		for _, want := range row.want {
			if !slices.Contains(got, want) {
				t.Errorf("lateColonListElements(%q, windows=%t) = %q, missing %q", row.value, row.windows, got, want)
			}
		}
		if whole != row.whole {
			t.Errorf("lateColonListElements(%q, windows=%t) whole = %t, want %t", row.value, row.windows, whole, row.whole)
		}
	}
}
